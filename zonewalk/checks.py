"""
DNS record lookups and hosting-provider detection for zonewalk.

Every ``check_*`` function in this module performs one logical DNS
or domain-lifecycle check, mutates a :class:`ZonewalkState` object
to record findings, and prints human-readable results immediately.
"""

import subprocess
import re
from typing import Optional

from zonewalk.utils import Style, section, subsection, ok, fail, warn, info, note, days_until


# ---------------------------------------------------------------------------
# Constants – hosting-provider and competitor signatures
# ---------------------------------------------------------------------------

# Known 1-grid nameserver hostnames and their hosting-platform descriptions.
# Used by ``check_ns_and_provider`` to determine whether the domain is
# hosted with 1-grid and what control-panel it runs on.
GRID_NS_MAP: dict[str, str] = {
    "petra": "Windows Plesk",
    "thor": "Linux Plesk",
    "linus": "Linux cPanel (1)",
    "hostserv": "Linux cPanel (2)",
    "lnxwzdns": "Website Design",
    "myserver": "Business VPS",
    "openprovider": "OpenProvider (.com)",
}

# Competitor / external DNS provider signatures (substring match against
# the full NS-record output).
COMPETITOR_MAP: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("hetzner", "Hetzner/xneelo"),
    ("xneelo", "xneelo"),
    ("hostafrica", "Host Africa"),
    ("afrihost", "Afrihost"),
    ("google", "Google Workspace"),
    ("outlook", "Microsoft 365"),
    ("amazon", "AWS Route53"),
    ("azure", "Azure DNS"),
    ("godaddy", "GoDaddy"),
]


# ---------------------------------------------------------------------------
# Low-level helpers – wrappers around external DNS tools
# ---------------------------------------------------------------------------


def _dig(record_type: str, name: str, server: Optional[str] = None) -> str:
    """Run ``dig +short <type> <name>`` and return the output.

    If *server* is provided the query is sent to that specific resolver
    (used for the propagation table).  Returns an empty string on any
    error (timeout, tool missing, NXDOMAIN).
    """
    cmd = ["dig", "+short", record_type, name]
    if server:
        cmd = ["dig", f"@{server}", "+short", record_type, name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _dig_full(record_type: str, name: str) -> str:
    """Run ``dig <type> <name>`` (full output) — used for SOA parsing."""
    try:
        result = subprocess.run(
            ["dig", record_type, name],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _host(ip: str) -> str:
    """Run ``host <ip>`` for reverse-DNS lookups when available."""
    try:
        result = subprocess.run(
            ["host", ip], capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _has_cmd(cmd: str) -> bool:
    """Return ``True`` when *cmd* is available on ``$PATH``."""
    try:
        subprocess.run(["which", cmd], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Shared state object
# ---------------------------------------------------------------------------


class ZonewalkState:
    """Mutable bag of findings collected during a zonewalk run.

    Every check function receives an instance of this class, reads from
    and writes to it as it performs its work.  The CLI module uses the
    collected data for the summary, ticket response, and fix guide.
    """

    def __init__(self) -> None:
        self.domain: str = ""                # target domain
        self.ip: str = ""                    # resolved A-record IP
        self.is_grid: bool = False           # hosted on 1-grid nameservers?
        self.provider: str = "Unknown / External"
        self.hosting_type: str = ""          # e.g. "Linux cPanel (1)"
        self.has_spf: bool = False
        self.has_mc: bool = False            # MailChannels in SPF?
        self.has_dmarc: bool = False
        self.dmarc_weak: bool = False        # policy = "none" or missing
        self.has_dkim: bool = False
        self.has_mx: bool = False
        self.has_a: bool = False
        self.has_ptr: bool = False
        self.issue: str = "standard"         # active --issue mode
        self.issues: list[str] = []          # issue codes for summary/guide


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------


def check_ns_and_provider(state: ZonewalkState) -> None:
    """Resolve NS records and identify the hosting provider.

    Matches returned nameservers against the :data:`GRID_NS_MAP` and
    :data:`COMPETITOR_MAP` tables.  Flags domains that are not on
    1-grid infrastructure (unless they use Cloudflare DNS).
    """
    section("Nameserver & Hosting Detection")
    ns_recs = _dig("NS", state.domain)

    if not ns_recs:
        fail("No NS records found.")
        state.issues.append("NO_NS")
        return

    # Print every NS record verbatim
    for ns in ns_recs.splitlines():
        print(f"    {ns}")

    # Check against known 1-grid nameserver hostnames
    for ns in ns_recs.splitlines():
        for key, val in GRID_NS_MAP.items():
            if key.lower() in ns.lower():
                state.is_grid = True
                state.provider = "1-grid"
                state.hosting_type = val

    # Fall through to competitor detection if not 1-grid
    if not state.is_grid:
        for pattern, name in COMPETITOR_MAP:
            if pattern.lower() in ns_recs.lower():
                state.provider = name
                break

    # Print hosting verdict
    if state.is_grid:
        hosting = f" ({state.hosting_type})" if state.hosting_type else ""
        print(f"\n  {Style.OK} Hosted with 1-grid{hosting}")
    elif "cloudflare" in ns_recs.lower():
        print(f"\n  {Style.WARN} DNS managed via Cloudflare (changes must be made there)")
        state.provider = "Cloudflare"
    else:
        print(f"\n  {Style.FAIL} Not hosted with 1-grid - Provider: {state.provider}")
        state.issues.append("NOT_GRID")


def whois_summary(state: ZonewalkState) -> None:
    """Query the domain registrar via ``whois`` and check expiry.

    Only available when the ``whois`` tool is installed on the machine.
    Flags domains that are expired or expiring within 30 days.
    """
    section("Domain Registration & Expiry")
    if not _has_cmd("whois"):
        warn("whois not installed")
        return

    try:
        result = subprocess.run(
            ["whois", state.domain], capture_output=True, text=True, timeout=15,
        )
        data = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        warn("whois lookup failed")
        return

    # Extract registrar, expiry date, and domain status from free-form whois text
    expiry = ""
    registrar = ""
    status = ""

    for line in data.splitlines():
        low = line.lower()
        if "registrar:" in low and not registrar:
            registrar = line.split(":", 1)[1].strip()
        if any(x in low for x in ["expiry", "expires", "expiration date"]):
            val = line.split(":", 1)[1].strip() if ":" in line else ""
            if val and not expiry:
                expiry = val
        if low.startswith("status:") and not status:
            val = line.split(":", 1)[1].strip() if ":" in line else ""
            if val:
                status = (status + " " + val).strip()

    if registrar:
        info(f"Registrar: {registrar}")
    if expiry:
        info(f"Expires:   {expiry}")
    if status:
        info(f"Status:    {status}")

    # Calculate days until expiry and flag urgency
    if expiry:
        days = days_until(expiry)
        if days is not None:
            if days < 0:
                fail(f"DOMAIN EXPIRED {abs(days)} days ago!")
                state.issues.append("DOMAIN_EXPIRED")
            elif days < 14:
                fail(f"EXPIRES IN {days} DAYS - Urgent!")
                state.issues.append("EXPIRY_CRITICAL")
            elif days < 30:
                warn(f"Expires in {days} days")
            else:
                ok(f"{days} days until expiry")


def check_a_record(state: ZonewalkState) -> None:
    """Resolve the A record for the domain and extract the primary IP."""
    section("A Record & IP Info")
    a_rec = _dig("A", state.domain)

    if not a_rec:
        fail("No A record found.")
        state.issues.append("NO_A_RECORD")
        return

    state.has_a = True
    state.ip = a_rec.splitlines()[0]
    ok(f"A record: {a_rec}")
    note(f"Primary IP: {state.ip}")

    count = len(a_rec.splitlines())
    if count > 1:
        info(f"Multiple A records ({count})")


def ptr_check(state: ZonewalkState) -> None:
    """Perform a reverse-DNS (PTR) lookup on the A-record IP.

    PTR records (also called reverse DNS) are required by many mail
    servers (especially Gmail) to accept inbound mail.  Missing or
    mismatched PTR records are a common cause of deliverability issues.
    """
    section("Reverse DNS (PTR)")
    if not state.ip:
        warn("No A record - skipping PTR")
        return

    info(f"PTR for {state.ip}")

    # Prefer `host` if available as it's more user-friendly; fall back to dig
    ptr = ""
    if _has_cmd("host"):
        host_out = _host(state.ip)
        match = re.search(r"domain name pointer (\S+)", host_out)
        if match:
            ptr = match.group(1).rstrip(".")
    else:
        ptr_result = _dig("PTR", state.ip)
        if ptr_result:
            ptr = ptr_result.splitlines()[0].rstrip(".")

    if not ptr:
        fail("No PTR record found")
        warn("Missing PTR affects Gmail delivery")
        note("PTRs are set at IP block level - contact 1-grid support")
        state.has_ptr = False
        state.issues.append("NO_PTR")
    else:
        ok(f"PTR: {ptr}")
        state.has_ptr = True
        if state.domain.lower() in ptr.lower():
            ok("PTR matches domain")
        else:
            warn(f"PTR ({ptr}) does not match {state.domain}")


def ptr_consistency_check(state: ZonewalkState) -> None:
    """Audit the full PTR -> A forward-confirm chain.

    A proper PTR setup requires that the PTR hostname resolves *back*
    to the same A-record IP.  When this chain is broken, email
    authentication (and thus deliverability) can fail.
    """
    section("PTR / A / Hostname Consistency Audit")
    if not state.ip:
        fail("No A record - cannot check PTR consistency")
        return

    ptr = _dig("PTR", state.ip)
    if ptr:
        ptr = ptr.splitlines()[0].rstrip(".")

    print(f"\n  A record:    {state.ip}")
    print(f"  PTR record:  {ptr or 'NONE'}")
    print(f"  Server host: {ptr or 'NONE'}")

    if not ptr:
        fail("No PTR record - Gmail/Outlook will flag as spam")
        state.issues.append("NO_PTR")
    else:
        ptr_a = _dig("A", ptr)
        ptr_a_ip = ptr_a.splitlines()[0] if ptr_a else ""
        print(f"\n  Forward-confirm: {ptr} -> {ptr_a_ip if ptr_a_ip else 'NONE'}")
        if ptr_a_ip == state.ip:
            ok("Forward-confirm (PTR -> A) PASS")
        else:
            fail(f"Forward-confirm FAIL - PTR points to {ptr} which resolves to {ptr_a_ip}")
            state.issues.append("PTR_FORWARD_FAIL")


def check_mx(state: ZonewalkState) -> None:
    """Resolve and validate MX records (mail routing).

    Checks that MX records are present and that each MX hostname
    resolves to at least one IP address.
    """
    section("MX Records (Mail Routing)")
    mx_recs = _dig("MX", state.domain)

    if not mx_recs:
        fail("No MX records found")
        state.issues.append("NO_MX")
        return

    state.has_mx = True
    ok("MX Records:")
    for mx_line in mx_recs.splitlines():
        print(f"    {mx_line}")
        parts = mx_line.split()
        if len(parts) >= 2:
            mx_host = parts[1]
            mx_ip = _dig("A", mx_host)
            if not mx_ip:
                fail(f"MX host {mx_host} does not resolve!")
                state.issues.append("MX_NO_RESOLVE")


def check_mail_auth(state: ZonewalkState) -> None:
    """Audit SPF, DKIM, and DMARC records for the domain.

    Mail authentication is the single most common cause of Gmail
    rejection.  This function checks all three mechanisms and reports
    both missing records and misconfigurations (e.g. SPF lookups >10,
    DMARC policy = ``none``, no DKIM signing selector).
    """
    section("Mail Authentication (SPF / DKIM / DMARC)")

    # ---- SPF ----
    subsection("SPF")
    all_txt = _dig("TXT", state.domain)
    spf = ""
    for line in all_txt.splitlines():
        if "v=spf" in line.lower():
            spf = line
            break

    if not spf:
        fail("No SPF record found")
        note('Fix: v=spf1 a mx include:relay.mailchannels.net ~all')
        state.issues.append("NO_SPF")
    else:
        state.has_spf = True
        ok(spf)
        if "mailchannels" in spf.lower():
            state.has_mc = True
            ok("MailChannels authorised")
        else:
            fail("MailChannels NOT in SPF")
            state.issues.append("NO_MAILCHANNELS")

        lookup_count = spf.lower().count("include:")
        if lookup_count > 8:
            warn("SPF lookups >8 - risk of PermError")
            state.issues.append("SPF_TOO_MANY_LOOKUPS")

    # ---- DKIM ----
    subsection("DKIM")
    dkim_found = False
    # Common DKIM selector names; the first match wins
    for selector in ["default", "selector1", "selector2", "google", "mail",
                     "dkim", "k1", "zoho", "s1", "s2", "smtp", "email", "mimecast"]:
        result = _dig("TXT", f"{selector}._domainkey.{state.domain}")
        if result:
            dkim_found = True
            state.has_dkim = True
            ok(f"DKIM found (selector: {selector})")
            p_match = re.search(r'p=([A-Za-z0-9+/=]+)', result)
            if p_match:
                key_preview = p_match.group(1)[:80]
                print(f"    Key: {key_preview}...")
            break

    if not dkim_found:
        fail("No DKIM record found")
        state.issues.append("NO_DKIM")

    # ---- DMARC ----
    subsection("DMARC")
    dmarc = _dig("TXT", f"_dmarc.{state.domain}")
    if dmarc:
        dmarc_clean = dmarc.replace('"', "").strip()
        state.has_dmarc = True
        ok(dmarc_clean)
        policy_match = re.search(r'p=(\w+)', dmarc_clean)
        if policy_match:
            policy = policy_match.group(1)
            if policy == "reject":
                ok("Policy: REJECT (strongest)")
            elif policy == "quarantine":
                info("Policy: QUARANTINE")
            elif policy == "none":
                state.dmarc_weak = True
                fail("Policy: NONE - no enforcement")
                state.issues.append("DMARC_NONE")

        if "rua=" in dmarc.lower():
            rua_match = re.search(r'rua=([^;]+)', dmarc_clean)
            if rua_match:
                info(f"Reports: {rua_match.group(1)}")
        else:
            warn("No rua tag - no DMARC reports")
    else:
        fail("No DMARC record found")
        note(f"Fix: v=DMARC1; p=quarantine; rua=mailto:dmarc@{state.domain}")
        state.has_dmarc = False
        state.dmarc_weak = True
        state.issues.append("NO_DMARC")


def check_all_txt(state: ZonewalkState) -> None:
    """Dump every TXT record on the domain (including non-SPF entries)."""
    section("All TXT Records")
    txt_recs = _dig("TXT", state.domain)
    if not txt_recs:
        warn("No TXT records")
        return
    for line in txt_recs.splitlines():
        print(f"  {line}")


def check_soa(state: ZonewalkState) -> None:
    """Resolve the SOA record and report zone health parameters.

    The SOA serial, refresh, retry, expire, and minimum-TTL values
    are all displayed.  A missing SOA indicates a broken or missing
    DNS zone.
    """
    section("SOA Record (Zone Health)")
    soa_full = _dig_full("SOA", state.domain)
    soa_short = _dig("SOA", state.domain)

    if not soa_short:
        fail("No SOA record - zone may be broken")
        state.issues.append("NO_SOA")
        return

    ok(f"SOA: {soa_short}")
    parts = soa_short.split()
    if len(parts) >= 7:
        serial, refresh, retry, expire, ttl = parts[2:7]
        note(f"Serial: {serial}  Refresh: {refresh}s  Retry: {retry}s  Expire: {expire}s  Min-TTL: {ttl}s")


def check_ns_port53(state: ZonewalkState) -> None:
    """Test whether the authoritative nameserver responds on TCP/53.

    Some firewalls or misconfigured resolvers block TCP DNS, which
    breaks large responses (DNSSEC, many record types) and zone
    transfers.
    """
    section("DNS Port 53")
    ns_list = _dig("NS", state.domain)
    if not ns_list:
        return
    first_ns = ns_list.splitlines()[0]
    ns_ip = _dig("A", first_ns)
    if not ns_ip:
        return
    ns_ip = ns_ip.splitlines()[0]

    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        result = sock.connect_ex((ns_ip, 53))
        if result == 0:
            ok(f"Port 53 open on {ns_ip}")
        else:
            fail(f"Port 53 closed on {ns_ip}")
            state.issues.append("PORT53_CLOSED")
    finally:
        sock.close()
