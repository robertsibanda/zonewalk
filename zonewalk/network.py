import subprocess
import socket
import re
from datetime import datetime

from zonewalk.utils import Style, section, subsection, ok, fail, warn, info, note
from zonewalk.checks import ZonewalkState, _dig


COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 2083, 2087, 3306, 8080, 8443,
]
PORT_NAMES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS",
    995: "POP3S", 2083: "cPanel", 2087: "WHM", 3306: "MySQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

BLOCKLISTS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl-1.uceprotect.net", "UCEProtect L1"),
    ("psbl.surriel.com", "PSBL"),
]

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "pop3",
    "ftp", "cpanel", "whm", "plesk", "ns1", "ns2",
    "dev", "staging", "api", "admin", "portal", "secure", "vpn",
    "autodiscover", "autoconfig", "calendar", "contacts",
    "webdisk", "cpcalendars", "cpcontacts",
]


def _has_cmd(cmd: str) -> bool:
    try:
        subprocess.run(["which", cmd], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_web(state: ZonewalkState) -> None:
    section("Web / HTTP Check")
    if not _has_cmd("curl"):
        warn("curl not installed")
        return

    for proto in ("http", "https"):
        try:
            result = subprocess.run(
                ["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}",
                 f"{proto}://{state.domain}", "--max-time", "8", "-L"],
                capture_output=True, text=True, timeout=12,
            )
            code = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            code = "000"

        if code == "200":
            ok(f"{proto}://{state.domain} -> HTTP {code}")
        elif code in ("301", "302"):
            info(f"{proto} -> HTTP {code} Redirect")
        elif code == "403":
            warn(f"{proto} -> HTTP 403 Forbidden")
        elif code == "404":
            warn(f"{proto} -> HTTP 404")
            state.issues.append("HTTP_404")
        elif code in ("500", "502", "503"):
            fail(f"{proto} -> HTTP {code} Server Error")
            state.issues.append("HTTP_5XX")
        elif code == "000":
            fail(f"{proto} -> No response")
            state.issues.append("HTTP_NO_RESPONSE")
        else:
            warn(f"{proto} -> HTTP {code}")

    # SSL expiry check
    if not _has_cmd("openssl"):
        return
    try:
        ssl_proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{state.domain}:443",
             "-servername", state.domain, "-tlsextdebug"],
            input=b"Q\n", capture_output=True, text=True, timeout=12,
        )
        date_match = re.search(r"notAfter=(.*)", ssl_proc.stdout)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                exp_date = None
            if exp_date:
                days = (exp_date - datetime.now()).days
                if days < 0:
                    fail(f"SSL EXPIRED (was valid until {date_str})")
                    state.issues.append("SSL_EXPIRED")
                elif days < 14:
                    fail(f"SSL expires in {days} days ({date_str})")
                    state.issues.append("SSL_EXPIRY_CRITICAL")
                elif days < 30:
                    warn(f"SSL expires in {days} days")
                else:
                    ok(f"SSL valid for {days} days")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def ip_reputation_check(state: ZonewalkState) -> None:
    section("IP Reputation & Blocklist Check")
    if not state.ip:
        warn("No A record")
        return

    info(f"IP: {state.ip}")
    rev = ".".join(reversed(state.ip.split(".")))
    blocked = False

    for bl_host, bl_name in BLOCKLISTS:
        query = f"{rev}.{bl_host}"
        result = _dig("A", query)
        if result and "127.255.255.255" not in result and "NXDOMAIN" not in result:
            fail(f"LISTED on {bl_name}")
            blocked = True
            state.issues.append(f"IP_BLOCKED_{bl_name.replace(' ', '_')}")
        else:
            ok(f"Clean on {bl_name}")

    if blocked:
        print(f"\n  {Style.WARN} Delist at: https://www.spamhaus.org/lookup/")


def subdomain_enum(state: ZonewalkState) -> None:
    section("Subdomain Enumeration")
    info(f"Checking {len(COMMON_SUBDOMAINS)} subdomains...\n")
    found = 0
    for sub in COMMON_SUBDOMAINS:
        target = f"{sub}.{state.domain}"
        ip_result = _dig("A", target)
        cname_result = _dig("CNAME", target)
        if ip_result:
            ip = ip_result.splitlines()[0]
            ok(f"{target} -> {ip}")
            found += 1
        elif cname_result:
            cname = cname_result.splitlines()[0]
            info(f"{target} -> CNAME {cname}")
            found += 1

    if found == 0:
        info("No common subdomains found")
    print(f"\n  {found} subdomain(s) found")


def port_scan(state: ZonewalkState) -> None:
    section("Port Scan")
    info(f"Scanning {len(COMMON_PORTS)} ports...\n")
    for port in COMMON_PORTS:
        name = PORT_NAMES.get(port, "Unknown")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((state.domain, port))
            if result == 0:
                ok(f"Port {port} ({name}): OPEN")
            else:
                print(f"  {Style.GRAY}Port {port} ({name}): closed{Style.NC}")
        finally:
            sock.close()


def check_smtp_ports(state: ZonewalkState) -> None:
    subsection("SMTP Port Check")
    mx_recs = _dig("MX", state.domain)
    mx_host = "mail." + state.domain
    if mx_recs:
        first = mx_recs.splitlines()[0]
        parts = first.split()
        if len(parts) >= 2:
            mx_host = parts[1]

    for port in (25, 465, 587):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((mx_host, port))
            if result == 0:
                ok(f"Port {port} OPEN on {mx_host}")
            else:
                warn(f"Port {port} closed on {mx_host}")
        finally:
            sock.close()


def propagation_info(state: ZonewalkState) -> None:
    section("Global DNS Propagation (A Record)")
    expected = _dig("A", state.domain)
    if not expected:
        fail("No A record found")
        return

    expected_ip = expected.splitlines()[0]
    info(f"Expected: {expected_ip} (authoritative)")
    print()

    resolvers = [
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("Comcast (US)", "75.75.75.75"),
        ("OpenDNS (EU)", "208.67.220.220"),
        ("Yandex (RU)", "77.88.8.8"),
        ("Alibaba (AS)", "223.5.5.5"),
        ("Liquid ZA", "154.0.1.1"),
        ("Telkom ZA", "196.25.1.1"),
        ("Google (SA)", "8.8.4.4"),
        ("Telstra (AU)", "139.130.4.4"),
    ]

    print(f"{'Resolver':<24} {'IP':<15} {'Result':<15} Status")
    print("-" * 70)

    propagated = True
    for name, rip in resolvers:
        lookup = _dig("A", state.domain, server=rip)
        lookup_ip = lookup.splitlines()[0] if lookup else ""

        if not lookup_ip:
            print(f"{name:<24} {rip:<15} {'-':<15} {Style.FAIL}NO RECORD{Style.NC}")
            propagated = False
        elif lookup_ip == expected_ip:
            print(f"{name:<24} {rip:<15} {lookup_ip:<15} {Style.OK}MATCH{Style.NC}")
        else:
            print(f"{name:<24} {rip:<15} {lookup_ip:<15} {Style.FAIL}MISMATCH{Style.NC}")
            propagated = False

    print()
    if propagated:
        ok("Fully propagated - all resolvers return expected IP")
    else:
        warn("Still propagating - some resolvers differ from authoritative")

    print()
    section("Propagation Times Reference")
    print("  Record          Min         Max         Notes")
    print("  --------------------------------------------------------------")
    print("  Nameserver      12 hrs      48 hrs      ISPs cache aggressively")
    print("  MX Record       1 hr        24 hrs      Affects inbound email")
    print("  A/CNAME/TXT     15 min      4 hrs       Depends on TTL setting")
    print("  DMARC           15 min      4 hrs       Check dmarcian.com")
    print(f"\n  {Style.INFO} Track: https://dnschecker.org/")


def mail_header_analysis(state: ZonewalkState, header_source: str) -> None:
    from zonewalk.utils import header as hdr_print
    hdr_print("EMAIL HEADER ANALYSIS")

    if header_source == "-":
        print(f"  {Style.CYAN}Paste email headers below, then press Ctrl+D when done:{Style.NC}\n")
        import sys
        header_text = sys.stdin.read()
    else:
        try:
            with open(header_source) as f:
                header_text = f.read()
        except FileNotFoundError:
            fail(f"Header file not found: {header_source}")
            return

    if not header_text.strip():
        fail("No header input received")
        return

    info("Parsing email headers...\n")

    from_field = _extract_header(header_text, r"^From:\s*(.+)", r"^From:\s*(.+)")
    to_field = _extract_header(header_text, r"^To:\s*(.+)")
    subject = _extract_header(header_text, r"^Subject:\s*(.+)")
    date = _extract_header(header_text, r"^Date:\s*(.+)")
    return_path = _extract_header(header_text, r"^Return-Path:\s*(.+)")
    reply_to = _extract_header(header_text, r"^Reply-To:\s*(.+)")
    x_mailer = _extract_header(header_text, r"^X-Mailer:\s*(.+)")
    if not x_mailer:
        x_mailer = _extract_header(header_text, r"^User-Agent:\s*(.+)")

    print(f"  {Style.WHITE}Envelope:{Style.NC}")
    print(f"    From:         {from_field or 'N/A'}")
    if return_path:
        print(f"    Return-Path:  {return_path.strip('<>')}")
    if reply_to:
        print(f"    Reply-To:     {reply_to}")
    print(f"    To:           {to_field or 'N/A'}")
    print(f"    Subject:      {subject or 'N/A'}")
    print(f"    Date:         {date or 'N/A'}")
    if x_mailer:
        print(f"    Sender Agent: {x_mailer}")

    print()
    print(f"  {Style.WHITE}Spoofing Checks:{Style.NC}")
    from_domain = _extract_domain(from_field)
    rp_domain = _extract_domain(return_path)
    if from_domain and rp_domain:
        if from_domain.lower() == rp_domain.lower():
            ok(f"From domain matches Return-Path ({from_domain})")
        else:
            fail(f"From/Return-Path MISMATCH: From={from_domain}  Return-Path={rp_domain}")
            warn("Possible spoofing or third-party sender")
    if reply_to:
        rt_domain = _extract_domain(reply_to)
        if rt_domain and from_domain and rt_domain.lower() != from_domain.lower():
            warn(f"Reply-To domain ({rt_domain}) differs from From domain ({from_domain}) - phishing indicator")

    # Authentication Results
    print()
    print(f"  {Style.WHITE}Authentication Results:{Style.NC}")
    auth_lines = re.findall(r"^Authentication-Results:.+", header_text, re.MULTILINE | re.IGNORECASE)
    if auth_lines:
        auth_text = " ".join(auth_lines)
        spf_res = _extract_auth(auth_text, "spf")
        dkim_res = _extract_auth(auth_text, "dkim")
        dmarc_res = _extract_auth(auth_text, "dmarc")

        ok(f"SPF:   {spf_res.upper()}") if spf_res == "pass" else fail(f"SPF:   {spf_res or 'not checked'}")
        ok(f"DKIM:  {dkim_res.upper()}") if dkim_res == "pass" else fail(f"DKIM:  {dkim_res or 'not checked'}")
        ok(f"DMARC: {dmarc_res.upper()}") if dmarc_res == "pass" else fail(f"DMARC: {dmarc_res or 'not checked'}")

        arc_match = re.search(r"ARC-Authentication-Results:.*?dmarc=(\S+)", header_text, re.DOTALL)
        if arc_match:
            info(f"ARC:   {arc_match.group(1)} (forwarded mail)")

        # DKIM domain alignment
        dkim_sig = re.search(r"DKIM-Signature:.*?d=([^;\s]+)", header_text, re.DOTALL)
        if dkim_sig and from_domain:
            dkim_domain = dkim_sig.group(1)
            if dkim_domain.lower() == from_domain.lower():
                ok(f"DKIM domain aligned ({dkim_domain})")
            else:
                warn(f"DKIM domain ({dkim_domain}) != From domain ({from_domain}) - DMARC alignment fail")
    else:
        warn("No Authentication-Results header found")

    # Spam Score
    print()
    print(f"  {Style.WHITE}Spam Score:{Style.NC}")
    spam_status = _extract_header(header_text, r"^X-Spam-Status:\s*(.+)")
    spam_score = _extract_header(header_text, r"^X-Spam-Score:\s*(.+)")
    spam_level = _extract_header(header_text, r"^X-Spam-Level:\s*(.+)")
    if spam_status:
        print(f"    Status: {spam_status}")
    if spam_score:
        print(f"    Score:  {spam_score}")
    if spam_level:
        print(f"    Level:  {spam_level}")
    if not any([spam_status, spam_score, spam_level]):
        print("    No X-Spam headers found")

    # Originating IP
    print()
    print(f"  {Style.WHITE}Originating IP:{Style.NC}")
    received = re.findall(r"^Received:[^\n]+(?:\\n[ \t]+[^\n]+)*", header_text, re.MULTILINE)
    orig_ip = None
    if received:
        last = received[-1]
        ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", last)
        if not ip_match:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", last)
        if ip_match:
            orig_ip = ip_match.group(1)

    if orig_ip:
        print(f"    IP: {orig_ip}")
        orig_ptr = _dig("PTR", orig_ip)
        if orig_ptr:
            print(f"    PTR: {orig_ptr.splitlines()[0].rstrip('.')}")
        else:
            warn("No PTR for originating IP")
        rev = ".".join(reversed(orig_ip.split(".")))
        listed = _dig("A", f"{rev}.zen.spamhaus.org")
        if listed and "127.255.255.255" not in listed:
            fail("Originating IP listed on Spamhaus ZEN!")
        else:
            ok("Originating IP clean on Spamhaus ZEN")
    else:
        print("    Could not extract originating IP")

    # Hop-by-hop trace
    print()
    print(f"  {Style.WHITE}Hop-by-Hop Trace (newest first -> oldest last):{Style.NC}")
    prev_time = None
    total_hops = len(received)
    for i, line in enumerate(received):
        hop_num = i + 1
        hop_from = re.search(r"from\s+(\S+)", line)
        hop_by = re.search(r"\bby\s+(\S+)", line)
        hop_with = re.search(r"\bwith\s+(\S+)", line)
        hop_time = re.search(r";\s+(.+)", line)

        delay = ""
        if hop_time:
            try:
                t = hop_time.group(1).strip()
                parsed = _parse_date(t)
                if parsed and prev_time:
                    diff = int((prev_time - parsed).total_seconds())
                    if diff >= 60:
                        delay = f" {Style.YELLOW}[+{diff // 60}m {diff % 60}s delay]{Style.NC}"
                    else:
                        delay = f" {Style.GRAY}[+{diff}s]{Style.NC}"
                if parsed:
                    prev_time = parsed
            except (ValueError, AttributeError):
                pass

        src = hop_from.group(1) if hop_from else "?"
        dst = hop_by.group(1) if hop_by else "?"
        w = hop_with.group(1) if hop_with else "?"
        print(f"    Hop {hop_num}: {src} -> {dst} ({w}){delay}")
        if hop_time:
            print(f"           {Style.GRAY}{hop_time.group(1).strip()}{Style.NC}")
    print(f"    {total_hops} hop(s) total")

    # Block reason analysis
    print()
    print(f"  {Style.WHITE}Block / Rejection Analysis:{Style.NC}")
    reason = None
    if re.search(r"550-5\.7\.1", header_text, re.IGNORECASE):
        reason = "Gmail 550-5.7.1: Unauthenticated - SPF/DKIM/DMARC failure"
    elif re.search(r"550-5\.7\.26", header_text, re.IGNORECASE):
        reason = "Gmail 550-5.7.26: ARC authentication failed (forwarded mail)"
    elif re.search(r"4\.7\.26", header_text, re.IGNORECASE):
        reason = "Gmail 4.7.26: Unauthenticated email from domain"
    elif re.search(r"spf=(hardfail|fail)", header_text, re.IGNORECASE):
        reason = "SPF hardfail: Sender IP not authorised for this domain"
    elif re.search(r"dkim=fail", header_text, re.IGNORECASE):
        reason = "DKIM fail: Signature invalid or domain mismatch"
    elif re.search(r"dmarc=fail", header_text, re.IGNORECASE):
        reason = "DMARC fail: Neither SPF nor DKIM passed alignment"
    elif re.search(r"550.*spam|spam.*550", header_text, re.IGNORECASE):
        reason = "550 SPAM: Content or IP reputation flagged"
    elif re.search(r"554.*reject|554.*denied", header_text, re.IGNORECASE):
        reason = "554 Rejected: Server policy or blocklist match"

    if reason:
        fail(reason)
    else:
        info("No explicit rejection pattern detected in headers")


def _extract_header(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_domain(field: str) -> str:
    if not field:
        return ""
    match = re.search(r"@([^>]+)", field)
    return match.group(1).strip() if match else ""


def _extract_auth(text: str, mechanism: str) -> str:
    match = re.search(rf"{mechanism}=(\S+)", text, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _parse_date(date_str: str):
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(date_str)
    except (ValueError, TypeError):
        return None
