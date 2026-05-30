"""
Command-line entry point for zonewalk.

Parses arguments with :mod:`argparse`, builds a :class:`ZonewalkState`,
and coordinates the check/display pipeline.  Handles the four
early-exit modes (``--guide``, ``--ptr``, ``--headers``, no domain)
before falling through to the full diagnostic run.
"""

import argparse
import sys
from datetime import datetime

from zonewalk.utils import Style, header, section, ok, fail, warn, info, note
from zonewalk.checks import (
    ZonewalkState,
    check_ns_and_provider,
    whois_summary,
    check_a_record,
    ptr_check,
    ptr_consistency_check,
    check_mx,
    check_mail_auth,
    check_all_txt,
    check_soa,
    check_ns_port53,
)
from zonewalk.network import (
    check_web,
    ip_reputation_check,
    subdomain_enum,
    port_scan,
    check_smtp_ports,
    propagation_info,
    mail_header_analysis,
)


# ---------------------------------------------------------------------------
# Issue-specific diagnostics (--issue flag)
# ---------------------------------------------------------------------------


def issue_diagnostic(state: ZonewalkState) -> None:
    """Run targeted checks based on the ``--issue`` value.

    Each branch gathers evidence relevant to the specific problem
    type (send mail, receive mail, web down, DNS failure, etc.)
    and prints a diagnosis checklist alongside the findings.
    """
    header(f"ISSUE DIAGNOSTIC: {state.issue.upper()}")

    if state.issue == "mail-send":
        # Outbound: mail-auth triple, SMTP port reachability,
        # IP reputation, and PTR completeness
        section("Outbound Mail Diagnosis")
        check_mail_auth(state)
        check_smtp_ports(state)
        ip_reputation_check(state)
        ptr_check(state)
        print()
        print("Root causes:")
        if not state.has_spf:
            fail("No SPF record")
        if not state.has_mc:
            fail("MailChannels not in SPF")
        if not state.has_dkim:
            fail("No DKIM signing")
        if state.dmarc_weak:
            fail("DMARC weak or missing")
        if not state.has_ptr:
            warn("No PTR record")
        if state.has_spf and state.has_dkim and not state.dmarc_weak:
            ok("SPF/DKIM/DMARC all pass")

    elif state.issue == "mail-recv":
        # Inbound: MX records, SMTP port 25/465/587
        section("Inbound Mail Diagnosis")
        check_mx(state)
        check_smtp_ports(state)
        print()
        print("Checklist:")
        note("1. MX records correct?")
        note("2. Port 25 open?")
        note("3. Mailbox quota full?")
        note("4. Spam folder?")
        note("5. Client settings: mail.{domain} port 993/465")

    elif state.issue == "web-down":
        section("Website Down Diagnosis")
        check_a_record(state)
        check_web(state)
        print()
        print("Checklist:")
        note("1. A record correct?")
        note("2. Web server running?")
        note("3. Firewall port 80/443?")
        note("4. Domain expired?")
        note("5. Check error_log")

    elif state.issue == "dns-fail":
        section("DNS Failure Diagnosis")
        check_soa(state)
        check_ns_port53(state)
        print()
        print("Checklist:")
        note("1. NS records exist?")
        note("2. named running?")
        note("3. Port 53 open?")
        note("4. Zone file valid?")

    elif state.issue == "propagation":
        propagation_info(state)

    elif state.issue == "wrong-domain":
        section("Wrong Domain Registration")
        info("Registry restriction: domain names cannot be changed after registration.")
        info("Options: 1) Register correct domain  2) Let incorrect domain expire")

    elif state.issue == "spam-received":
        section("Inbound Spam Analysis")
        info("Paste the full email headers when prompted.\n")
        mail_header_analysis(state, "-")


# ---------------------------------------------------------------------------
# Technician fix guide (--guide flag)
# ---------------------------------------------------------------------------


def technician_guide(state: ZonewalkState) -> None:
    """Print cPanel / Plesk repair instructions for each detected issue.

    The guide maps issue codes to step-by-step fix text that a
    front-line support engineer can follow verbatim.
    """
    header("TECHNICIAN FIX GUIDE")
    if not state.issues:
        print("  No issues to fix")
        return

    # Each entry is a tuple of instruction lines; {domain} is formatted
    # at print time from the current state.
    guides = {
        "NO_A_RECORD": (
            "FIX: A Record",
            'cPanel: Domains -> Zone Editor -> Manage -> + Add Record -> Type A\n  Name: @   Record: <IP>',
            'Plesk: Websites & Domains -> DNS Settings -> + Add Record -> Type A\n  Domain: {domain}.   IP: <IP>',
        ),
        "NO_SPF": (
            "FIX: SPF Record",
            'Add: v=spf1 a mx include:relay.mailchannels.net ~all',
            'cPanel Zone Editor -> Type TXT, Name: {domain}.',
            'Plesk DNS Settings -> Type TXT, Name: {domain}.',
        ),
        "NO_MAILCHANNELS": (
            "FIX: MailChannels in SPF",
            'Add: include:relay.mailchannels.net to existing SPF record',
        ),
        "NO_DKIM": (
            "FIX: DKIM",
            'cPanel: Email Deliverability -> Manage -> Enable DKIM',
            'Plesk: Websites & Domains -> Mail Settings -> Use DKIM',
        ),
        "NO_DMARC": (
            "FIX: DMARC",
            'Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}',
            'cPanel: Zone Editor -> Type TXT, Name: _dmarc',
            'Plesk: DNS Settings -> Type TXT, Name: _dmarc.{domain}.',
        ),
        "DMARC_NONE": (
            "FIX: DMARC Policy",
            'Change DMARC policy from "none" to "quarantine" or "reject"',
        ),
        "NO_MX": (
            "FIX: MX Records",
            'cPanel: Zone Editor -> + Add Record -> Type MX\n  Priority: 0   Destination: mail.{domain}.',
            '  Also add A record: mail -> <IP>',
            'Plesk: DNS Settings -> + Add Record -> Type MX',
        ),
        "NO_PTR": (
            "FIX: PTR Reverse DNS",
            'PTR is set at IP level - open ticket with 1-grid support',
            'Request: Set PTR for <IP> to mail.{domain}',
        ),
        "PTR_FORWARD_FAIL": (
            "FIX: PTR Forward-Confirm",
            'PTR points to a hostname that does not resolve back to the IP.',
            'Fix: Ensure PTR hostname has an A record pointing to the same IP.',
        ),
        "SSL_EXPIRED": (
            "FIX: SSL Certificate",
            "cPanel: SSL/TLS Status -> Run AutoSSL",
            "Plesk: Websites & Domains -> SSL/TLS Certificates -> Let's Encrypt -> Issue",
        ),
        "SSL_EXPIRY_CRITICAL": (
            "FIX: SSL Certificate Expiring",
            "cPanel: SSL/TLS Status -> Run AutoSSL",
            "Plesk: Websites & Domains -> SSL/TLS Certificates -> Let's Encrypt -> Issue",
        ),
        "HTTP_NO_RESPONSE": (
            "FIX: Web Server Down",
            'cPanel: systemctl restart httpd',
            'Plesk: Tools & Settings -> Services -> Restart nginx/apache',
        ),
        "DOMAIN_EXPIRED": (
            "FIX: Domain Renewal",
            'https://my.1-grid.com -> Domains -> My Domains -> Renew',
        ),
        "EXPIRY_CRITICAL": (
            "FIX: Domain Renewal",
            'https://my.1-grid.com -> Domains -> My Domains -> Renew',
        ),
        "NO_SOA": (
            "FIX: DNS Zone",
            'SSH: systemctl restart named; firewall-cmd --add-service=dns --permanent',
            'cPanel: Zone Editor -> check zone exists',
            'Plesk: DNS Settings -> check SOA',
        ),
        "PORT53_CLOSED": (
            "FIX: DNS Port 53",
            'SSH: systemctl restart named; firewall-cmd --add-service=dns --permanent',
        ),
    }

    for issue in state.issues:
        print()
        print("=" * 70)
        if issue in guides:
            for line in guides[issue]:
                print(line.format(domain=state.domain))
        elif issue.startswith("IP_BLOCKED"):
            print("FIX: IP Blocklisted")
            print("1. Check for compromised accounts")
            print("2. Change all email passwords")
            print("3. Delist: https://www.spamhaus.org/lookup/")
        elif issue == "NOT_GRID":
            print(f"NOTE: External DNS - {state.provider}")
            if state.provider == "Cloudflare":
                print("Cloudflare: https://dash.cloudflare.com/ -> DNS")

    print()
    print("Quick Reference:")
    print("  cPanel DNS path: Domains -> Zone Editor -> Manage")
    print("  Plesk DNS path:  Websites & Domains -> DNS Settings")


# ---------------------------------------------------------------------------
# Summary printers
# ---------------------------------------------------------------------------


def print_issue_summary(state: ZonewalkState) -> None:
    """Print a compact bullet list of all issues found."""
    if not state.issues:
        header("ALL CHECKS PASSED - No issues")
        return

    header(f"ISSUES SUMMARY ({len(state.issues)} found)")
    issue_labels = {
        "NO_NS": "No NS records",
        "NOT_GRID": f"External provider: {state.provider}",
        "NO_A_RECORD": "No A record",
        "NO_MX": "No MX records",
        "MX_NO_RESOLVE": "MX host does not resolve",
        "NO_SPF": "Missing SPF record",
        "NO_MAILCHANNELS": "MailChannels not in SPF",
        "SPF_TOO_MANY_LOOKUPS": "SPF too many lookups",
        "NO_DKIM": "No DKIM record",
        "NO_DMARC": "Missing DMARC",
        "DMARC_NONE": "DMARC policy is 'none'",
        "NO_PTR": "No PTR record",
        "PTR_FORWARD_FAIL": "PTR forward-confirm failed",
        "NO_SOA": "No SOA record",
        "PORT53_CLOSED": "Port 53 closed",
        "HTTP_404": "Website 404",
        "HTTP_5XX": "Website 5xx error",
        "HTTP_NO_RESPONSE": "Website not responding",
        "SSL_EXPIRED": "SSL EXPIRED",
        "SSL_EXPIRY_CRITICAL": "SSL expires <14 days",
        "DOMAIN_EXPIRED": "DOMAIN EXPIRED",
        "EXPIRY_CRITICAL": "Domain expires <14 days",
    }
    for issue in state.issues:
        if issue.startswith("IP_BLOCKED"):
            fail(f"IP on spam blocklist ({issue.removeprefix('IP_BLOCKED_')})")
        elif issue in issue_labels:
            label = issue_labels[issue]
            # Issues containing NO_, EXPIRED, BLOCKED, FAIL, or 5XX
            # are treated as failures; the rest are warnings.
            if any(w in issue for w in ["NO_", "EXPIRED", "BLOCKED", "FAIL", "5XX"]):
                fail(label)
            else:
                warn(label)
        else:
            warn(issue)


def auto_ticket_response(state: ZonewalkState) -> None:
    """Print a concise summary block suitable for pasting into a ticket.

    Includes domain, date, detected provider, the full list of issues
    in human-readable form, and a propagation reminder if DNS changes
    are involved.
    """
    header("DIAGNOSIS SUMMARY")
    print(f"Domain: {state.domain}")
    print(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Issue:  {state.issue.capitalize()}")
    hosting = f" ({state.hosting_type})" if state.hosting_type else ""
    print(f"Server: {state.provider}{hosting}")
    print()

    if not state.issues:
        print("No issues detected. All records appear correct.")
        return

    print("Issues Found:")
    for issue in state.issues:
        if issue == "NO_NS":
            fail("Nameserver records missing - domain not resolvable")
        elif issue == "NOT_GRID":
            warn(f"External provider: {state.provider}")
        elif issue == "NO_A_RECORD":
            fail("No A record - website will not load")
        elif issue == "NO_MX":
            fail("No MX records - inbound email fails")
        elif issue == "MX_NO_RESOLVE":
            fail("MX hostname does not resolve to an IP")
        elif issue == "NO_SPF":
            fail("SPF missing - outbound mail may be rejected")
        elif issue == "NO_MAILCHANNELS":
            fail("MailChannels not authorised in SPF")
        elif issue == "SPF_TOO_MANY_LOOKUPS":
            warn("SPF exceeds 10-lookup limit")
        elif issue == "NO_DKIM":
            fail("DKIM not configured - email not signed")
        elif issue == "NO_DMARC":
            fail("DMARC missing - Gmail/Yahoo may throttle")
        elif issue == "DMARC_NONE":
            warn("DMARC policy is 'none' - no enforcement")
        elif issue == "NO_PTR":
            warn("No PTR record - affects Gmail delivery")
        elif issue == "PTR_FORWARD_FAIL":
            fail("PTR forward-confirm broken")
        elif issue == "NO_SOA":
            fail("DNS zone missing or corrupt")
        elif issue == "PORT53_CLOSED":
            fail("Port 53 closed - nameserver unreachable")
        elif issue == "HTTP_404":
            warn("HTTP 404 - website files missing")
        elif issue == "HTTP_5XX":
            fail("HTTP 5xx - server-side error")
        elif issue == "HTTP_NO_RESPONSE":
            fail("Website not responding")
        elif issue == "SSL_EXPIRED":
            fail("SSL certificate EXPIRED")
        elif issue == "SSL_EXPIRY_CRITICAL":
            fail("SSL expiring within 14 days")
        elif issue == "DOMAIN_EXPIRED":
            fail("Domain has EXPIRED")
        elif issue == "EXPIRY_CRITICAL":
            fail("Domain expiring within 14 days")
        elif issue.startswith("IP_BLOCKED"):
            fail("IP on spam blocklist - mail delivery blocked")

    # Propagation reminder when DNS-related issues are present
    has_dns = any(i.startswith(("NO_", "DMARC_", "SSL_", "PORT53_", "PTR_")) for i in state.issues)
    if has_dns:
        print(f"\n  {Style.YELLOW}DNS changes made - allow propagation (up to 48h for NS, 4h for others){Style.NC}")
    print(f"\n  {Style.CYAN}Monitor: https://dnschecker.org/{Style.NC}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Build the argument parser, dispatch to the appropriate check path,
    and print the summary."""
    parser = argparse.ArgumentParser(
        prog="zonewalk",
        description="ZONEWALK v3.1 - DNS & Mail Diagnostics for cPanel/Plesk (Python port)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zonewalk example.co.za
  zonewalk example.co.za --issue mail-send
  zonewalk example.co.za --issue spam-received
  zonewalk example.co.za --ports
  zonewalk example.co.za --headers headers.txt
  cat headers.txt | zonewalk example.co.za --headers -
        """,
    )
    parser.add_argument("domain", nargs="?", help="Domain name to check")
    parser.add_argument("--deep", action="store_true", help="Subdomain enumeration")
    parser.add_argument("--ports", action="store_true", help="Common port scan")
    parser.add_argument("--ip-reputation", action="store_true", help="Blocklist check")
    parser.add_argument("--skip-propagation", action="store_true", help="Skip DNS propagation section")
    parser.add_argument("--guide", action="store_true", help="Print technician fix guide only")
    parser.add_argument("--ptr", action="store_true", help="Enhanced PTR vs A vs hostname consistency")
    parser.add_argument("--headers", nargs="?", const="-", metavar="FILE",
                        help="Parse email headers from file or - for stdin")
    parser.add_argument("--issue", choices=[
        "mail-send", "mail-recv", "web-down", "dns-fail",
        "propagation", "wrong-domain", "spam-received",
    ], default="standard", help="Specific issue to diagnose")

    args = parser.parse_args()

    state = ZonewalkState()

    # --headers triggers immediate header-analysis mode and exits
    if args.headers:
        mail_header_analysis(state, args.headers)
        return

    # No domain -> print usage
    if not args.domain:
        print("ZONEWALK v3.1 - DNS & Mail Diagnostics (Python port)")
        print("Usage: zonewalk domain.co.za [OPTIONS]")
        print()
        parser.print_help()
        sys.exit(1)

    state.domain = args.domain
    state.issue = args.issue

    # --ptr mode: A record + PTR consistency only
    if args.ptr:
        check_a_record(state)
        ptr_consistency_check(state)
        return

    # --guide mode: run only the checks needed to populate issues,
    # then print the fix guide
    if args.guide:
        check_ns_and_provider(state)
        check_a_record(state)
        check_mail_auth(state)
        technician_guide(state)
        return

    # ------------------------------------------------------------------
    # Full diagnostic run (default path)
    # ------------------------------------------------------------------
    header(f"ZONEWALK v3.1 - {state.domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Issue: {state.issue.capitalize()}")
    print()

    check_ns_and_provider(state)
    whois_summary(state)
    check_a_record(state)
    ptr_check(state)
    check_mx(state)
    check_mail_auth(state)
    check_all_txt(state)
    check_soa(state)

    if not args.skip_propagation:
        propagation_info(state)

    if args.issue != "standard":
        issue_diagnostic(state)
    if args.ip_reputation:
        ip_reputation_check(state)
    if args.deep:
        subdomain_enum(state)
    if args.ports:
        port_scan(state)

    print()
    print_issue_summary(state)
    print()
    auto_ticket_response(state)

    if state.issues:
        print(f"\n{Style.YELLOW}Tip: Run with --guide for fix steps{Style.NC}")


if __name__ == "__main__":
    main()
