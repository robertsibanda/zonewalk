#!/bin/bash

# =========================================================
# ZONEWALK :: OMNI-PROTOCOL v2.5
# AUTHOR: ROBERT.SIBANDA@1-GRID.COM
# ENHANCED: Full DNS diagnostics, canned responses,
#           mail filter checks, zone validation,
#           IP reputation, subdomain enum & more.
# =========================================================
#
# USAGE:
#   ./zonewalk.sh domain.co.za [OPTIONS]
#
# OPTIONS:
#   --issue mail-send     Diagnose outbound mail failures
#   --issue mail-recv     Diagnose inbound mail failures
#   --issue web-down      Diagnose website down
#   --issue dns-fail      Diagnose DNS resolution failures
#   --issue propagation   Explain propagation delays
#   --issue wrong-domain  Handle wrong domain registration
#   --deep                Enumerate subdomains
#   --ports               Scan common ports
#   --ip-reputation       Check IP against spam blocklists
#   --skip-propagation    Skip propagation section
#   --canned              Print all canned responses only
#   --guide               Print technician reference guide only
#
# EXAMPLES:
#   ./zonewalk.sh example.co.za --issue mail-send --ip-reputation
#   ./zonewalk.sh example.co.za --deep --ports
# =========================================================

DOMAIN=$1
shift

# -- Defaults --
RUN_DEEP=false
RUN_PORTS=false
CHECK_REP=false
SKIP_PROP=false
CANNED_ONLY=false
SHOW_GUIDE=false
ISSUE="standard"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --deep)             RUN_DEEP=true ;;
        --ports)            RUN_PORTS=true ;;
        --ip-reputation)    CHECK_REP=true ;;
        --skip-propagation) SKIP_PROP=true ;;
        --canned)           CANNED_ONLY=true ;;
        --guide)            SHOW_GUIDE=true ;;
        --issue)            ISSUE="$2"; shift ;;
        *) echo -e "Unknown parameter: $1\nRun with no args to see usage."; exit 1 ;;
    esac
    shift
done

if [ -z "$DOMAIN" ]; then
    echo -e "\nZONEWALK v2.5 -- 1-grid DNS & Mail Diagnostic Tool"
    echo -e "=================================================="
    echo -e "Usage: $0 domain.co.za [OPTIONS]\n"
    echo -e "Options:"
    echo -e "  --issue mail-send     Outbound mail failure"
    echo -e "  --issue mail-recv     Inbound mail failure"
    echo -e "  --issue web-down      Website not loading"
    echo -e "  --issue dns-fail      DNS not resolving"
    echo -e "  --issue propagation   Propagation delay query"
    echo -e "  --issue wrong-domain  Wrong domain registered"
    echo -e "  --deep                Subdomain enumeration"
    echo -e "  --ports               Port scan (common ports)"
    echo -e "  --ip-reputation       Blocklist / spam check"
    echo -e "  --canned              Print all canned responses"
    echo -e "  --guide               Print technician reference guide"
    echo ""
    exit 1
fi

# -- Colors --
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[1;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

OK="${GREEN}OK${NC}"
FAIL="${RED}FAIL${NC}"
WARN="${YELLOW}WARN${NC}"
INFO="${CYAN}INFO${NC}"

# -- Config --
GRID_NS=("petra" "thor" "linus" "hostserv" "lnxwzdns" "myserver" "openprovider")
GRID_NS_NAMES=(
    "petra=Windows Plesk"
    "thor=Linux Plesk"
    "linus=Linux cPanel (1)"
    "hostserv=Linux cPanel (2)"
    "lnxwzdns=Website Design"
    "myserver=Business VPS"
    "openprovider=OpenProvider (.com)"
)
COMPETITORS=(
    "cloudflare.com|Cloudflare"
    "hetzner.co.za|Hetzner/xneelo"
    "xneelo.co.za|xneelo"
    "hostafrica.com|Host Africa"
    "afrihost.com|Afrihost"
    "google.com|Google Workspace"
    "outlook.com|Microsoft 365"
    "amazon|AWS Route53"
    "azure|Azure DNS"
    "godaddy|GoDaddy"
)
COMMON_SUBDOMAINS=(www mail webmail smtp imap pop pop3 ftp cpanel whm plesk ns1 ns2 dev staging api admin portal secure vpn)
COMMON_PORTS=(21 22 25 53 80 110 143 443 465 587 993 995 2083 2087 3306 8080 8443)
PORT_NAMES=( "21=FTP" "22=SSH" "25=SMTP" "53=DNS" "80=HTTP" "110=POP3" "143=IMAP" "443=HTTPS" "465=SMTPS" "587=SMTP-Submission" "993=IMAPS" "995=POP3S" "2083=cPanel" "2087=WHM" "3306=MySQL" "8080=HTTP-Alt" "8443=HTTPS-Alt" )

# -- State vars --
IS_GRID=false
CURRENT_PROVIDER="Unknown / External"
HOSTING_TYPE=""
HAS_SPF=false
HAS_MC=false
HAS_DMARC=false
DMARC_WEAK=false
DMARC_POLICY=""
HAS_DKIM=false
HAS_MX=false
HAS_A=false
HAS_PTR=false
SMTP_OPEN=false
IMAP_OPEN=false
HTTP_CODE=""
ISSUES_FOUND=()

# =========================================================
# HELPERS
# =========================================================

header() {
    echo -e "\n${BLUE}==================================================${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

section() {
    echo -e "\n${MAGENTA}>> $1${NC}"
    echo -e "${MAGENTA}-------------------------------------------------${NC}"
}

subsection() {
    echo -e "\n  ${CYAN}* $1${NC}"
}

note() {
    echo -e "  ${GRAY}-> $1${NC}"
}

get_port_name() {
    local port=$1
    for entry in "${PORT_NAMES[@]}"; do
        if [[ "$entry" == "${por}t="* ]]; then
            echo "${entry#*=}"
            return
        fi
    done
    echo "Unknown"
}

# =========================================================
# CORE CHECKS
# =========================================================

check_ns_and_provider() {
    section "Nameserver & Hosting Detection"
    NS_RECS=$(dig +short NS "$DOMAIN" 2>/dev/null)

    if [ -z "$NS_RECS" ]; then
        echo -e "  $FAIL No NS records found. Domain may not be registered or DNS is broken."
        ISSUES_FOUND+=("NO_NS")
        return
    fi

    echo -e "  Nameservers:"
    for ns in $NS_RECS; do
        echo -e "    $ns"
    done

    for ns in $NS_RECS; do
        for entry in "${GRID_NS_NAMES[@]}"; do
            key="${entry%%=*}"
            val="${entry#*=}"
            if echo "$ns" | grep -qi "$key"; then
                IS_GRID=true
                CURRENT_PROVIDER="1-grid"
                HOSTING_TYPE="$val"
            fi
        done
    done

    if [ "$IS_GRID" = false ]; then
        for comp in "${COMPETITORS[@]}"; do
            iface=$(echo "$comp" | cut -d'|' -f1)
            name=$(echo "$comp" | cut -d'|' -f2)
            if echo "$NS_RECS" | grep -qi "$iface"; then
                CURRENT_PROVIDER="$name"
            fi
        done
    fi

    if [ "$IS_GRID" = true ]; then
        echo -e "\n  $OK Hosted with 1-grid"
        echo -e "  $INFO Hosting type: ${HOSTING_TYPE}"
    elif echo "$NS_RECS" | grep -qi "cloudflare"; then
        echo -e "\n  $WARN DNS managed via Cloudflare"
        echo -e "  $INFO Hosting may still be on 1-grid but DNS updates must be made in Cloudflare."
        CURRENT_PROVIDER="Cloudflare"
    else
        echo -e "\n  $FAIL Not hosted with 1-grid -- Provider: ${CURRENT_PROVIDER}"
        ISSUES_FOUND+=("NOT_GRID")
    fi
}

whois_summary() {
    section "Domain Registration & Expiry"
    if ! command -v whois &>/dev/null; then
        echo -e "  $WARN whois not installed. Skipping."
        return
    fi
    WHOIS_DATA=$(whois "$DOMAIN" 2>/dev/null)
    EXPIRY=$(echo "$WHOIS_DATA" | grep -iE "expiry|expires|Expiration Date|Expiry Date" | head -1 | sed 's/.*: //')
    REGISTRAR=$(echo "$WHOIS_DATA" | grep -iE "registrar:" | head -1 | sed 's/.*: //')
    STATUS=$(echo "$WHOIS_DATA" | grep -iE "status:" | head -3 | sed 's/.*: //' | tr '\n' ' ')

    [ ! -z "$REGISTRAR" ] && echo -e "  $INFO Registrar: ${REGISTRAR}"
    [ ! -z "$EXPIRY"    ] && echo -e "  $INFO Expires:   ${EXPIRY}"
    [ ! -z "$STATUS"    ] && echo -e "  $INFO Status:    ${STATUS}"

    if [ ! -z "$EXPIRY" ]; then
        EXP_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        if [ ! -z "$EXP_EPOCH" ]; then
            DAYS_LEFT=$(( (EXP_EPOCH - NOW_EPOCH) / 86400 ))
            if [ "$DAYS_LEFT" -lt 0 ]; then
                echo -e "  $FAIL DOMAIN EXPIRED ${DAYS_LEFT#-} days ago!"
                ISSUES_FOUND+=("DOMAIN_EXPIRED")
            elif [ "$DAYS_LEFT" -lt 14 ]; then
                echo -e "  $FAIL EXPIRES IN ${DAYS_LEFT} DAYS -- Urgent renewal required!"
                ISSUES_FOUND+=("EXPIRY_CRITICAL")
            elif [ "$DAYS_LEFT" -lt 30 ]; then
                echo -e "  $WARN Expires in ${DAYS_LEFT} days -- renewal recommended soon."
            else
                echo -e "  $OK ${DAYS_LEFT} days until expiry."
            fi
        fi
    fi
}

check_a_record() {
    section "A Record & IP Info"
    A_REC=$(dig +short A "$DOMAIN" 2>/dev/null)
    if [ -z "$A_REC" ]; then
        echo -e "  $FAIL No A record found. Website will not load."
        ISSUES_FOUND+=("NO_A_RECORD")
    else
        HAS_A=true
        IP=$(echo "$A_REC" | head -1)
        echo -e "  $OK A record: ${A_REC}"
        note "Primary IP: $IP"
        COUNT=$(echo "$A_REC" | wc -l)
        [ "$COUNT" -gt 1 ] && echo -e "  $INFO Multiple A records found (${COUNT}). Verify all are correct."
    fi
}

ptr_check() {
    section "Reverse DNS (PTR)"
    IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    if [ -z "$IP" ]; then
        echo -e "  $WARN No A record found -- skipping PTR check."
        return
    fi

    echo -e "  $INFO Checking PTR for IP: ${IP}"

    if command -v host &>/dev/null; then
        HOST_OUT=$(host "$IP" 2>/dev/null)
        PTR=$(echo "$HOST_OUT" | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
    else
        PTR=$(dig +short -x "$IP" 2>/dev/null | grep -v "^;;\|NXDOMAIN\|SERVFAIL" | sed 's/\.$//' | head -1)
    fi

    PTR=$(echo "$PTR" | grep -v "^\s*$" | grep -vE "^[0-9]|NXDOMAIN|SERVFAIL|not found|connection" | head -1)

    if [ -z "$PTR" ]; then
        echo -e "  $FAIL No PTR record found for $IP"
        echo -e "  $WARN Missing PTR affects Gmail delivery -- mail may be rejected or go to spam."
        note "PTR records are managed by whoever owns the IP block (usually the hosting provider)."
        note "For 1-grid hosted servers, contact support to have a PTR record added."
        HAS_PTR=false
        ISSUES_FOUND+=("NO_PTR")
    else
        echo -e "  $OK PTR found: $IP -> $PTR"
        HAS_PTR=true
        if echo "$PTR" | grep -qi "$DOMAIN"; then
            echo -e "  $OK PTR matches domain -- good for mail delivery."
        else
            echo -e "  $WARN PTR ($PTR) does not match $DOMAIN"
            note "This may cause soft rejections on strict mail servers."
        fi
    fi
}

check_mx() {
    section "MX Records (Mail Routing)"
    MX_RECS=$(dig +short MX "$DOMAIN" 2>/dev/null)
    if [ -z "$MX_RECS" ]; then
        echo -e "  $FAIL No MX records found. Incoming email will fail."
        ISSUES_FOUND+=("NO_MX")
    else
        HAS_MX=true
        echo -e "  $OK MX Records:"
        while IFS= read -r mx; do
            echo -e "    $mx"
            MX_HOST=$(echo "$mx" | awk '{print $2}')
            MX_IP=$(dig +short A "$MX_HOST" 2>/dev/null | head -1)
            if [ -z "$MX_IP" ]; then
                echo -e "    $FAIL MX host $MX_HOST does not resolve to an IP!"
                ISSUES_FOUND+=("MX_NO_RESOLVE")
            else
                note "$MX_HOST -> $MX_IP"
            fi
        done <<< "$MX_RECS"
    fi
}

check_mail_auth() {
    section "Mail Authentication (SPF / DKIM / DMARC / MailChannels)"

    subsection "SPF"
    SPF=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i "v=spf")
    if [ -z "$SPF" ]; then
        echo -e "  $FAIL No SPF record found."
        echo -e "  $WARN Without SPF, receiving servers cannot verify your mail is legitimate."
        note "Fix: Add TXT record: v=spf1 include:relay.mailchannels.net ~all"
        ISSUES_FOUND+=("NO_SPF")
    else
        HAS_SPF=true
        echo -e "  $OK $SPF"

        if echo "$SPF" | grep -qi "mailchannels"; then
            HAS_MC=true
            echo -e "  $OK MailChannels included -- 1-grid outbound relay authorised."
        else
            echo -e "  $FAIL MailChannels NOT in SPF (relay.mailchannels.net missing)."
            echo -e "  $WARN Outbound mail via 1-grid may be rejected or flagged as spam."
            note "Fix: Add 'include:relay.mailchannels.net' to your SPF record."
            note "Example: v=spf1 a mx include:relay.mailchannels.net ~all"
            ISSUES_FOUND+=("NO_MAILCHANNELS")
        fi

        LOOKUP_COUNT=$(echo "$SPF" | grep -o "include:" | wc -l)
        if [ "$LOOKUP_COUNT" -gt 8 ]; then
            echo -e "  $WARN SPF has $LOOKUP_COUNT includes -- risk of exceeding 10 DNS lookup limit."
            ISSUES_FOUND+=("SPF_TOO_MANY_LOOKUPS")
        fi
    fi

    subsection "DKIM"
    DKIM_FOUND=false
    for selector in default selector1 selector2 google mail dkim k1 zoho; do
        RESULT=$(dig +short TXT "${selector}._domainkey.${DOMAIN}" 2>/dev/null)
        if [ ! -z "$RESULT" ]; then
            DKIM_FOUND=true
            HAS_DKIM=true
            echo -e "  $OK DKIM found (selector: $selector)"
            note "$RESULT" | head -c 120
            echo ""
            break
        fi
    done
    if [ "$DKIM_FOUND" = false ]; then
        echo -e "  $FAIL No DKIM record found on common selectors."
        echo -e "  $WARN Without DKIM, emails lack cryptographic signing -- Gmail/Yahoo may reject."
        note "Selectors checked: default, selector1, selector2, google, mail, dkim, k1, zoho"
        ISSUES_FOUND+=("NO_DKIM")
    fi

    subsection "DMARC"
    DMARC=$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | tr -d '"')
    if [ -z "$DMARC" ]; then
        echo -e "  $FAIL No DMARC record found."
        echo -e "  $WARN Gmail & Yahoo require DMARC for bulk senders. Mail may go to spam."
        note "Fix: Add TXT record at _dmarc.$DOMAIN"
        note "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN"
        HAS_DMARC=false
        DMARC_WEAK=true
        ISSUES_FOUND+=("NO_DMARC")
    else
        HAS_DMARC=true
        echo -e "  $OK $DMARC"
        DMARC_POLICY=$(echo "$DMARC" | grep -oP 'p=\K[^;]+' | tr -d ' ' | cut -d';' -f1)
        case "$DMARC_POLICY" in
            reject)
                echo -e "  $OK Policy: REJECT -- strongest protection."
                ;;
            quarantine)
                echo -e "  Policy: QUARANTINE -- failing mail goes to spam."
                ;;
            none)
                DMARC_WEAK=true
                echo -e "  $FAIL Policy: NONE -- no enforcement. Spoofing is possible."
                note "Fix: Change p=none to p=quarantine or p=reject"
                ISSUES_FOUND+=("DMARC_NONE")
                ;;
        esac

        if echo "$DMARC" | grep -qi "rua="; then
            RUA=$(echo "$DMARC" | grep -oP 'rua=\K[^;]+')
            echo -e "  $INFO Aggregate reports sent to: $RUA"
        else
            echo -e "  $WARN No rua tag -- you won't receive DMARC failure reports."
        fi
    fi
}

check_all_txt() {
    section "All TXT Records"
    TXT_RECS=$(dig +short TXT "$DOMAIN" 2>/dev/null)
    if [ -z "$TXT_RECS" ]; then
        echo -e "  $WARN No TXT records found."
    else
        echo -e "TXT records for $DOMAIN:"
        echo "$TXT_RECS" | while IFS= read -r line; do
            echo -e "  $line"
        done
    fi
}

check_soa() {
    section "SOA Record (Zone Health)"
    SOA=$(dig +short SOA "$DOMAIN" 2>/dev/null)
    if [ -z "$SOA" ]; then
        echo -e "  $FAIL No SOA record found -- DNS zone may be missing or broken."
        ISSUES_FOUND+=("NO_SOA")
    else
        echo -e "  $OK SOA: ${SOA}"
        SERIAL=$(echo "$SOA" | awk '{print $3}')
        REFRESH=$(echo "$SOA" | awk '{print $4}')
        RETRY=$(echo "$SOA" | awk '{print $5}')
        EXPIRE=$(echo "$SOA" | awk '{print $6}')
        TTL=$(echo "$SOA" | awk '{print $7}')
        note "Serial: $SERIAL  Refresh: ${REFRESH}s  Retry: ${RETRY}s  Expire: ${EXPIRE}s  Min-TTL: ${TTL}s"
    fi
}

check_ns_port53() {
    section "DNS Port 53 (named/BIND)"
    IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    NS_IP=$(dig +short NS "$DOMAIN" 2>/dev/null | head -1 | xargs dig +short A 2>/dev/null | head -1)

    for TARGET_IP in "$NS_IP" "$IP"; do
        [ -z "$TARGET_IP" ] && continue
        (echo >/dev/tcp/"$TARGET_IP"/53) 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "  $OK Port 53 open on $TARGET_IP"
        else
            echo -e "  $FAIL Port 53 closed/filtered on $TARGET_IP -- DNS queries may fail."
            ISSUES_FOUND+=("PORT53_CLOSED")
        fi
        break
    done
}

check_smtp_ports() {
    subsection "SMTP Port Check"
    MX_HOST=$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n | head -1 | awk '{print $2}')
    [ -z "$MX_HOST" ] && MX_HOST="mail.$DOMAIN"

    for port in 25 465 587; do
        (echo >/dev/tcp/"$MX_HOST"/"$port") 2>/dev/null \
            && echo -e "  $OK Port $port OPEN on $MX_HOST" \
            || echo -e "  $WARN Port $port closed on $MX_HOST"
    done
}

check_web() {
    section "Web / HTTP Check"
    if ! command -v curl &>/dev/null; then
        echo -e "  $WARN curl not installed. Skipping web check."
        return
    fi
    for proto in "http" "https"; do
        CODE=$(curl -o /dev/null -s -w "%{http_code}" "$proto://$DOMAIN" --max-time 8 -L 2>/dev/null)
        case "$CODE" in
            200) echo -e "  $OK $proto://$DOMAIN -> HTTP $CODE OK" ;;
            301|302) echo -e "  $INFO $proto://$DOMAIN -> HTTP $CODE Redirect" ;;
            403) echo -e "  $WARN $proto://$DOMAIN -> HTTP 403 Forbidden" ;;
            404) echo -e "  $WARN $proto://$DOMAIN -> HTTP 404 Not Found" ; ISSUES_FOUND+=("HTTP_404") ;;
            500|502|503) echo -e "  $FAIL $proto://$DOMAIN -> HTTP $CODE Server Error" ; ISSUES_FOUND+=("HTTP_5XX") ;;
            000) echo -e "  $FAIL $proto://$DOMAIN -> No response / connection refused" ; ISSUES_FOUND+=("HTTP_NO_RESPONSE") ;;
            *) echo -e "  $WARN $proto://$DOMAIN -> HTTP $CODE" ;;
        esac
        HTTP_CODE=$CODE
    done

    SSL_EXPIRY=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | grep notAfter | sed 's/notAfter=//')
    if [ ! -z "$SSL_EXPIRY" ]; then
        echo -e "  $INFO SSL expires: ${SSL_EXPIRY}"
        SSL_EPOCH=$(date -d "$SSL_EXPIRY" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        if [ ! -z "$SSL_EPOCH" ]; then
            SSL_DAYS=$(( (SSL_EPOCH - NOW_EPOCH) / 86400 ))
            if [ "$SSL_DAYS" -lt 0 ]; then
                echo -e "  $FAIL SSL CERTIFICATE EXPIRED!"
                ISSUES_FOUND+=("SSL_EXPIRED")
            elif [ "$SSL_DAYS" -lt 14 ]; then
                echo -e "  $FAIL SSL expires in $SSL_DAYS days -- renew immediately!"
                ISSUES_FOUND+=("SSL_EXPIRY_CRITICAL")
            elif [ "$SSL_DAYS" -lt 30 ]; then
                echo -e "  $WARN SSL expires in $SSL_DAYS days."
            else
                echo -e "  $OK SSL valid for $SSL_DAYS days."
            fi
        fi
    fi
}

ip_reputation_check() {
    section "IP Reputation & Blocklist Check"
    IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    if [ -z "$IP" ]; then
        echo -e "  $WARN No A record -- skipping reputation check."
        return
    fi
    echo -e "  $INFO Checking IP: ${IP}"
    REV=$(echo "$IP" | awk -F. '{print $4"."$3"."$2"."$1}')

    BLOCKLISTS=(
        "zen.spamhaus.org|Spamhaus ZEN"
        "bl.spamcop.net|SpamCop"
        "dnsbl.sorbs.net|SORBS"
        "b.barracudacentral.org|Barracuda"
        "dnsbl-1.uceprotect.net|UCEProtect L1"
        "psbl.surriel.com|PSBL"
    )

    BLOCKED=false
    for entry in "${BLOCKLISTS[@]}"; do
        bl=$(echo "$entry" | cut -d'|' -f1)
        name=$(echo "$entry" | cut -d'|' -f2)
        RESULT=$(dig +short "${REV}.${bl}" 2>/dev/null)
        if [ ! -z "$RESULT" ] && [ "$RESULT" != "127.255.255.255" ]; then
            echo -e "  $FAIL LISTED on $name ($bl) -> $RESULT"
            BLOCKED=true
            ISSUES_FOUND+=("IP_BLOCKED_$name")
        else
            echo -e "  $OK Clean on $name"
        fi
    done

    if [ "$BLOCKED" = true ]; then
        echo -e "\n  $WARN IP is on one or more blocklists. This will cause mail delivery failures."
        note "Request delisting at each blocklist provider's website."
        note "Spamhaus: https://www.spamhaus.org/lookup/"
        note "Barracuda: https://www.barracudacentral.org/rbl/removal-request"
    fi
}

subdomain_enum() {
    section "Subdomain Enumeration"
    echo -e "  Checking ${#COMMON_SUBDOMAINS[@]} common subdomains...\n"
    FOUND_COUNT=0
    for sub in "${COMMON_SUBDOMAINS[@]}"; do
        TARGET="${sub}.${DOMAIN}"
        IP=$(dig +short A "$TARGET" 2>/dev/null | head -1)
        CNAME=$(dig +short CNAME "$TARGET" 2>/dev/null | head -1)
        if [ ! -z "$IP" ]; then
            echo -e "  $OK $TARGET -> $IP"
            FOUND_COUNT=$((FOUND_COUNT+1))
        elif [ ! -z "$CNAME" ]; then
            echo -e "  $INFO $TARGET -> CNAME: $CNAME"
            FOUND_COUNT=$((FOUND_COUNT+1))
        fi
    done
    [ "$FOUND_COUNT" -eq 0 ] && echo -e "  $INFO No common subdomains found."
    echo -e "\n  $FOUND_COUNT subdomain(s) discovered."
}

port_scan() {
    section "Port Scan"
    echo -e "  Scanning ${#COMMON_PORTS[@]} ports on $DOMAIN...\n"
    for P in "${COMMON_PORTS[@]}"; do
        PNAME=$(get_port_name "$P")
        (echo >/dev/tcp/"$DOMAIN"/"$P") 2>/dev/null \
            && echo -e "  $OK Port $P ($PNAME): OPEN" \
            || echo -e "  Port $P ($PNAME): closed"
    done
}

# =========================================================
# PROPAGATION INFO + GL BAL CHECK
# =========================================================

propagation_info() {
    section "Global DNS Propagation (A Record)"

    EXPECTED=$(dig +short A "$DOMAIN" | head -1)

    if [ -z "$EXPECTED" ]; then
        echo -e "  $FAIL No local A record found to compare against."
        return
    fi

    printf "%-25s %-15s %-15s\n" "Region / Location" "Resolver" "Result"
    echo "----------------------------------------------------------------------"

    RESOLVERS=(
        "Google (Global)|8.8.8.8"
        "Cloudflare (Global)|1.1.1.1"
        "Comcast (US East)|75.75.75.75"
        "Cisco OpenDNS (Europe)|208.67.220.220"
        "Yandex (Russia)|77.88.8.8"
        "Alibaba (Asia)|223.5.5.5"
        "Liquid ZA (South Africa)|154.0.1.1"
        "Telkom ZA (South Africa)|196.25.1.1"
        "Google (South America)|8.8.4.4"
        "Telstra (Australia)|139.130.4.4"
    )

    for line in "${RESOLVERS[@]}"; do
        NAME=$(echo "$line" | cut -d'|' -f1)
        RIP=$(echo "$line" | cut -d'|' -f2)

        LOOKUP=$(dig @$RIP +short A "$DOMAIN" +time=1 +tries=1 | head -1)

        if [ "$LOOKUP" == "$EXPECTED" ]; then
            STATUS="MATCH"
        elif [ -z "$LOOKUP" ]; then
            STATUS="NO RECORD"
        else
            STATUS="MISMATCH"
        fi

        printf "%-25s %-15s %-15s\n" "$NAME" "$RIP" "$STATUS"
    done

    echo ""
    section "DNS Propagation Times Reference"
    echo -e "  Record Type      Min Time     Max Time     Notes"
    echo   "  ----------------------------------------------------------------"
    printf "  %-17s %-13s %-13s %s\n" "Nameserver (NS)"  "12 hours"  "48 hours" "ISPs cache aggressively"
    printf "  %-17s %-13s %-13s %s\n" "MX Record"        "1 hour"    "24 hours" "Affects inbound email"
    printf "  %-17s %-13s %-13s %s\n" "A/CNAME Record"   "15 min"    "4 hours"  "Depends on TTL"
    printf "  %-17s %-13s %-13s %s\n" "TXT/SPF/DKIM"     "15 min"    "4 hours"  "Gmail may cache longer"
    printf "  %-17s %-13s %-13s %s\n" "DMARC"            "15 min"    "4 hours"  "Check dmarcian.com"
    echo ""
    echo -e "  $INFO Check propagation: https://dnschecker.org/"
}

# =========================================================
# TECHNICIAN REFERENCE GUIDE
# =========================================================

technician_guide() {
    header "TECHNICIAN REFERENCE -- How to Fix Each Issue"

    if [ ${#ISSUES_FOUND[@]} -eq 0 ]; then
        echo -e "  No issues detected. No fixes needed."
    fi

    for issue in "${ISSUES_FOUND[@]}"; do
        echo ""
        echo "======================================================================"
        case $issue in
            NO_A_RECORD)
                echo "FIX: Missing A Record"
                echo "======================================================================"
                echo ""
                echo "cPanel Zone Editor:"
                echo "  1. cPanel -> Domains -> Zone Editor"
                echo "  2. Find domain -> Manage"
                echo "  3. + Add Record"
                echo "     Type:    A"
                echo "     Name:    @"
                echo "     Record:  <server-ip>"
                echo "     TTL:     14400"
                echo ""
                echo "Plesk DNS Settings:"
                echo "  1. Plesk -> Websites & Domains"
                echo "  2. Click DNS Settings for the domain"
                echo "  3. + Add Record"
                echo "     Type:    A"
                echo "     Domain:  ${DOMAIN}."
                echo "     IP:      <server-ip>"
                ;;

            NO_SPF|NO_MAILCHANNELS)
                echo "FIX: SPF Record Issue"
                echo "======================================================================"
                echo ""
                echo "Recommended SPF:"
                echo "  v=spf1 a mx include:relay.mailchannels.net ~all"
                echo ""
                echo "cPanel: Zone Editor -> + Add Record -> Type TXT"
                echo "  Name: ${DOMAIN}.   Record: v=spf1 a mx include:relay.mailchannels.net ~all"
                echo ""
                echo "Plesk: DNS Settings -> + Add Record -> Type TXT"
                echo "  Name: ${DOMAIN}.   Value: v=spf1 a mx include:relay.mailchannels.net ~all"
                ;;

            NO_DMARC|DMARC_NONE)
                echo "FIX: DMARC Record"
                echo "======================================================================"
                echo ""
                echo "Recommended DMARC:"
                echo "  v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}"
                echo ""
                echo "cPanel: Zone Editor -> + Add Record -> Type TXT"
                echo "  Name: _dmarc   Record: v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}"
                echo ""
                echo "Plesk: DNS Settings -> + Add Record -> Type TXT"
                echo "  Name: _dmarc.${DOMAIN}.   Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}"
                ;;

            NO_DKIM)
                echo "FIX: DKIM Record"
                echo "======================================================================"
                echo ""
                echo "cPanel: Email Deliverability -> Manage -> Enable DKIM"
                echo "  (cPanel auto-adds the TXT record)"
                echo ""
                echo "Plesk: Websites & Domains -> Mail Settings"
                echo "  -> Enable Use DKIM spam protection"
                ;;

            NO_MX)
                echo "FIX: MX Records"
                echo "======================================================================"
                echo ""
                echo "cPanel: Zone Editor -> + Add Record -> Type MX"
                echo "  Priority: 0   Destination: mail.${DOMAIN}."
                echo "  Then add: A record mail -> <server-ip>"
                echo ""
                echo "Plesk: DNS Settings -> + Add Record -> Type MX"
                echo "  Priority: 0   Mail server: mail.${DOMAIN}."
                ;;

            NO_PTR)
                echo "FIX: PTR / Reverse DNS"
                echo "======================================================================"
                echo ""
                echo "NOTE: PTR is set at IP block level, NOT in cPanel/Plesk."
                echo "  1. Open ticket with 1-grid/datacenter support"
                echo "  2. Request: Set PTR for <IP> to mail.${DOMAIN}"
                ;;

            SSL_EXPIRED|SSL_EXPIRY_CRITICAL)
                echo "FIX: SSL Certificate"
                echo "======================================================================"
                echo ""
                echo "cPanel: SSL/TLS Status -> Run AutoSSL"
                echo ""
                echo "Plesk: Websites & Domains -> SSL/TLS Certificates"
                echo "  -> Let's Encrypt -> Issue"
                ;;

            HTTP_NO_RESPONSE)
                echo "FIX: Website Not Responding"
                echo "======================================================================"
                echo ""
                echo "cPanel: SSH -> systemctl restart httpd"
                echo "Plesk: Tools & Settings -> Services -> Restart nginx/apache"
                ;;

            HTTP_5XX)
                echo "FIX: Server Error (5xx)"
                echo "======================================================================"
                echo ""
                echo "Check error_log in document root."
                echo "cPanel: Metrics -> Errors"
                echo "Common: file permissions, PHP version, script errors."
                ;;

            HTTP_404)
                echo "FIX: 404 Not Found"
                echo "======================================================================"
                echo ""
                echo "Verify files exist in public_html/ or document root."
                echo "cPanel: Domains -> check Document Root path."
                ;;

            DOMAIN_EXPIRED|EXPIRY_CRITICAL)
                echo "FIX: Domain Renewal"
                echo "======================================================================"
                echo ""
                echo "  1. Login https://my.1-grid.com"
                echo "  2. Domains -> My Domains -> Renew"
                ;;

            NO_SOA|PORT53_CLOSED)
                echo "FIX: DNS Zone / Nameserver Issue"
                echo "======================================================================"
                echo ""
                echo "  1. SSH into server: systemctl status named"
                echo "  2. systemctl restart named"
                echo "  3. firewall-cmd --add-service=dns --permanent"
                echo "  4. firewall-cmd --reload"
                echo ""
                echo "cPanel: Zone Editor -> check if domain appears -> Manage"
                echo "Plesk: Websites & Domains -> DNS Settings -> check SOA"
                ;;

            NOT_GRID)
                echo "NOTE: External DNS Provider"
                echo "======================================================================"
                echo ""
                echo "  DNS managed by ${CURRENT_PROVIDER}."
                echo "  Customer must update records at their provider's DNS panel."
                if [ "$CURRENT_PROVIDER" = "Cloudflare" ]; then
                    echo "  Cloudflare: https://dash.cloudflare.com/ -> DNS tab"
                fi
                ;;
        esac
    done

    echo ""
    header "QUICK REFERENCE -- Record Types"
    echo "  Type    Name              Value                              TTL"
    echo "  ----------------------------------------------------------------"
    echo "  A       @                 <IPv4>                            14400"
    echo "  MX      @                 mail.${DOMAIN}. (priority 0)      14400"
    echo "  TXT     @                 v=spf1 ... ~all                   14400"
    echo "  TXT     _dmarc            v=DMARC1; p=quarantine; ...       14400"
    echo "  TXT     default._domainkey v=DKIM1; h=sha256; p=...        14400"
    echo ""
    echo "  cPanel path:  Domains -> Zone Editor -> Manage"
    echo "  Plesk path:   Websites & Domains -> DNS Settings"
    echo "  Cloudflare:   dash.cloudflare.com -> DNS -> Add Record"
}

# =========================================================
# ISSUE SUMMARY
# =========================================================

print_issue_summary() {
    if [ ${#ISSUES_FOUND[@]} -eq 0 ]; then
        header "ALL CHECKS PASSED -- No issues detected"
        echo -e "  Domain appears healthy."
        return
    fi

    header "ISSUES SUMMARY (${#ISSUES_FOUND[@]} found)"
    for issue in "${ISSUES_FOUND[@]}"; do
        case $issue in
            NO_NS)              echo -e "  $FAIL No NS records -- domain not resolvable" ;;
            NOT_GRID)           echo -e "  $WARN Not hosted on 1-grid" ;;
            NO_A_RECORD)        echo -e "  $FAIL No A record -- website will not load" ;;
            NO_MX)              echo -e "  $FAIL No MX records -- inbound email will fail" ;;
            MX_NO_RESOLVE)      echo -e "  $FAIL MX host does not resolve" ;;
            NO_SPF)             echo -e "  $FAIL Missing SPF record" ;;
            NO_MAILCHANNELS)    echo -e "  $FAIL MailChannels not in SPF" ;;
            SPF_TOO_MANY_LOOKUPS) echo -e "  $WARN SPF too many DNS lookups" ;;
            NO_DKIM)            echo -e "  $FAIL No DKIM record" ;;
            NO_DMARC)           echo -e "  $FAIL Missing DMARC" ;;
            DMARC_NONE)         echo -e "  $WARN DMARC policy is none" ;;
            NO_PTR)             echo -e "  $WARN No PTR record" ;;
            NO_SOA)             echo -e "  $FAIL No SOA record" ;;
            PORT53_CLOSED)      echo -e "  $FAIL Port 53 closed" ;;
            HTTP_404)           echo -e "  $WARN Website 404 Not Found" ;;
            HTTP_5XX)           echo -e "  $FAIL Website server error (5xx)" ;;
            HTTP_NO_RESPONSE)   echo -e "  $FAIL Website not responding" ;;
            SSL_EXPIRED)        echo -e "  $FAIL SSL certificate EXPIRED" ;;
            SSL_EXPIRY_CRITICAL) echo -e "  $FAIL SSL expiring within 14 days" ;;
            DOMAIN_EXPIRED)     echo -e "  $FAIL DOMAIN HAS EXPIRED" ;;
            EXPIRY_CRITICAL)    echo -e "  $FAIL Domain expiring within 14 days" ;;
            IP_BLOCKED*)        echo -e "  $FAIL Server IP listed on spam blocklist" ;;
        esac
    done
}

# =========================================================
# DYNAMIC AUTO TICKET RESPONSE
# =========================================================

auto_ticket_response() {
    header "AUTO-GENERATED TICKET RESPONSE"
    echo ""

    # Opening based on issue mode
    case $ISSUE in
        mail-send)  echo "Thank you for contacting 1-grid Support regarding outbound email delivery on ${DOMAIN}." ;;
        mail-recv)  echo "Thank you for contacting 1-grid Support regarding inbound email issues on ${DOMAIN}." ;;
        web-down)   echo "Thank you for reporting that your website ${DOMAIN} is not loading." ;;
        dns-fail)   echo "Thank you for reporting DNS issues with ${DOMAIN}." ;;
        propagation) echo "Thank you for your query about DNS propagation for ${DOMAIN}." ;;
        wrong-domain) echo "Thank you for contacting us about the domain registration for ${DOMAIN}." ;;
        *)
            echo "Thank you for contacting 1-grid Support regarding ${DOMAIN}."
            echo "We have reviewed the configuration and provide our findings below."
            ;;
    esac
    echo ""

    # External DNS warning
    if [ "$IS_GRID" = false ] && [ "$CURRENT_PROVIDER" = "Cloudflare" ]; then
        echo "============================================"
        echo "IMPORTANT: Your DNS is managed via Cloudflare."
        echo "All record changes must be made in your Cloudflare account:"
        echo "https://dash.cloudflare.com/"
        echo "============================================"
        echo ""
    elif [ "$IS_GRID" = false ]; then
        echo "NOTE: Your DNS is managed by ${CURRENT_PROVIDER}."
        echo "DNS updates must be applied at that provider."
        echo ""
    fi

    # Issues found
    if [ ${#ISSUES_FOUND[@]} -gt 0 ]; then
        echo "============================================"
        echo "ISSUES IDENTIFIED AND RESOLVED"
        echo "============================================"
        echo ""

        for issue in "${ISSUES_FOUND[@]}"; do
            case $issue in
                NO_A_RECORD)     echo "  * Added missing A record - your domain now points to your server IP." ;;
                NO_MX)           echo "  * Added MX records - inbound email routing is now configured." ;;
                NO_SPF)          echo "  * Added SPF record - receiving servers can now verify your mail." ;;
                NO_MAILCHANNELS) echo "  * Added MailChannels to SPF - 1-grid relay is now authorised." ;;
                NO_DKIM)         echo "  * DKIM signing enabled - your emails are now cryptographically signed." ;;
                NO_DMARC)        echo "  * DMARC record added - Gmail/Yahoo policy is now enforced." ;;
                DMARC_NONE)      echo "  * DMARC policy updated from 'none' to 'quarantine'." ;;
                NO_PTR)          echo "  * PTR delisting request submitted to datacenter." ;;
                NO_SOA)          echo "  * DNS zone restored on nameserver." ;;
                PORT53_CLOSED)   echo "  * DNS port 53 reopened - nameserver now reachable." ;;
                SSL_EXPIRED)     echo "  * SSL certificate renewed." ;;
                SSL_EXPIRY_CRITICAL) echo "  * SSL certificate renewed before expiry." ;;
                DOMAIN_EXPIRED)  echo "  * Domain has been renewed." ;;
                EXPIRY_CRITICAL) echo "  * Domain has been renewed for another term." ;;
                HTTP_404)        echo "  * Website returning 404 - please verify files exist in the document root." ;;
                HTTP_5XX)        echo "  * Website returning server error - check error_log for details." ;;
                HTTP_NO_RESPONSE) echo "  * Web server restarted - ports 80/443 now responding." ;;
            esac
        done
        echo ""
        echo "All corrections have been applied on our side."
        echo ""
    fi

    # DNS change means propagation notice
    HAS_DNS=false
    for i in "${ISSUES_FOUND[@]}"; do
        case $i in
            NO_A_RECORD|NO_MX|NO_SPF|NO_MAILCHANNELS|NO_DKIM|NO_DMARC|DMARC_NONE|NO_NS|NO_SOA|NOT_GRID)
                HAS_DNS=true ;;
        esac
    done

    if [ "$HAS_DNS" = true ]; then
        echo "============================================"
        echo "PROPAGATION - What to Expect"
        echo "============================================"
        echo ""
        echo "DNS changes do not take effect instantly. They spread across"
        echo "the internet gradually as ISPs update their cached records."
        echo ""
        echo "  Record Type      Time to Propagate"
        echo "  --------------------------------------------"
        echo "  A / CNAME / TXT    15 min - 4 hours"
        echo "  MX / SPF / DKIM    1 hour - 24 hours"
        echo "  DMARC              15 min - 4 hours"
        echo "  Nameserver (NS)    12 hours - 48 hours"
        echo ""
        echo "During this window, some users may see old records while"
        echo "others see the new ones. This is normal and temporary."
        echo ""
        echo "Track progress: https://dnschecker.org/"
        echo ""
    fi

    # Closing
    echo "============================================"
    echo "NEXT STEPS"
    echo "============================================"
    echo ""

    if [ ${#ISSUES_FOUND[@]} -gt 0 ]; then
        echo "  1. Allow up to 48 hours for DNS propagation (if DNS was changed)"
        echo "  2. Clear your local DNS cache:"
        echo "     Windows: ipconfig /flushdns"
        echo "     macOS:   sudo dscacheutil -flushcache"
        echo "     Linux:   sudo systemd-resolve --flush-caches"
        echo "  3. Test your services after propagation"
        echo "  4. If issues persist, reply to this ticket"
        echo ""
    else
        echo "  No configuration issues were found on our side."
        echo "  If you are still experiencing problems, please check:"
        echo "  1. Your internet connection and local network"
        echo "  2. Whether the issue is isolated to one device"
        echo "  3. Whether other websites/services work correctly"
        echo ""
    fi

    echo "Kind regards,"
    echo "1-grid Support Team"
    echo ""
    echo "--------------------------------------------"
    echo "Diagnostic run: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Domain: ${DOMAIN}  |  Issues found: ${#ISSUES_FOUND[@]}"
    echo "--------------------------------------------"
}

# =========================================================
# ISSUE-SPECIFIC DIAGNOSTICS
# =========================================================

issue_diagnostic() {
    header "ISSUE DIAGNOSTIC: ${ISSUE^^}"

    case $ISSUE in
        mail-send)
            section "Outbound Mail Diagnosis"
            check_mail_auth
            check_smtp_ports
            ip_reputation_check
            ptr_check
            echo ""
            echo "Likely causes of outbound mail failure:"
            [ "$HAS_SPF" = false ]  && echo "  $FAIL No SPF record"
            [ "$HAS_MC" = false ]   && echo "  $FAIL MailChannels not in SPF"
            [ "$HAS_DKIM" = false ] && echo "  $FAIL No DKIM signing"
            [ "$DMARC_WEAK" = true ] && echo "  $FAIL DMARC policy too weak or missing"
            [ "$HAS_PTR" = false ]  && echo "  $WARN No PTR record"
            ;;

        mail-recv)
            section "Inbound Mail Diagnosis"
            check_mx
            check_smtp_ports
            echo ""
            echo "Inbound mail troubleshooting steps:"
            note "1. Verify MX records point to correct mail server"
            note "2. Check mail server is reachable on port 25"
            note "3. Confirm mailbox exists and quota is not full"
            note "4. Check spam/junk folder"
            note "5. Verify correct client settings: mail.$DOMAIN"
            ;;

        web-down)
            section "Website Down Diagnosis"
            check_a_record
            check_web
            echo ""
            echo "Website down troubleshooting steps:"
            note "1. Confirm A record points to correct server IP"
            note "2. Check if web server (nginx/apache) is running"
            note "3. Verify firewall allows port 80 and 443"
            note "4. Check if domain has expired"
            note "5. Review error logs on server"
            ;;

        dns-fail)
            section "DNS Failure Diagnosis"
            check_soa
            check_ns_port53
            echo ""
            echo "DNS failure troubleshooting steps:"
            note "1. Confirm NS records exist and resolve"
            note "2. Check named/BIND is running: systemctl status named"
            note "3. Verify port 53 is open on nameserver IP"
            note "4. Check named.conf for zone file errors"
            note "5. Review /var/log/messages for BIND errors"
            ;;

        propagation)
            propagation_info
            ;;

        wrong-domain)
            section "Wrong Domain Registration"
            echo "  This is a registry-level restriction."
            echo "  Domain names cannot be changed after registration."
            echo "  Customer must register a new domain with the correct name."
            echo ""
            echo "Recommended actions:"
            note "1. Register the correctly spelled domain as a new purchase"
            note "2. Let the incorrect domain expire at renewal date"
            note "3. Set up a redirect from the old domain if needed"
            ;;
    esac
}

# =========================================================
# CANNED RESPONSES (static, use --canned to view all)
# =========================================================

canned_responses() {
    echo "=== CANNED RESPONSES - 1-GRID SUPPORT ==="
    echo ""
    echo "Run ./zonewalk.sh <domain> to get dynamic responses"
    echo "tailored to the specific issues found."
}

# =========================================================
# MAIN EXECUTION
# =========================================================

if [ "$CANNED_ONLY" = true ]; then
    canned_responses
    exit 0
fi

if [ "$SHOW_GUIDE" = true ]; then
    check_ns_and_provider
    check_a_record
    check_mail_auth
    technician_guide
    exit 0
fi

header "ZONEWALK v2.5 -- $DOMAIN"
echo -e "  Started: $(date '+%Y-%m-%d %H:%M:%S')  |  Issue: $ISSUE"
echo ""

check_ns_and_provider
whois_summary
check_a_record
ptr_check
check_mx
check_mail_auth
check_all_txt
check_soa

[ "$SKIP_PROP" = false ] && propagation_info

if [ "$ISSUE" != "standard" ]; then
    issue_diagnostic
fi

[ "$CHECK_REP" = true ] && ip_reputation_check
[ "$RUN_DEEP"  = true ] && subdomain_enum
[ "$RUN_PORTS" = true ] && port_scan

print_issue_summary
echo ""
auto_ticket_response

if [ ${#ISSUES_FOUND[@]} -gt 0 ]; then
    echo ""
    echo "============================================"
    echo "TECHNICIAN: Run with --guide for step-by-step"
    echo "fix instructions for cPanel and Plesk."
    echo "============================================"
fi
