#!/bin/bash

# =========================================================
# ZONEWALK :: OMNI-PROTOCOL v3.1
# AUTHOR: ROBERT.SIBANDA@1-GRID.COM
# DESC:   L3 DNS + Mail diagnostics with remote SSH checks
# =========================================================
#
# USAGE:
#   ./zonewalk.sh domain.co.za [OPTIONS]
#
# OPTIONS:
#   --issue mail-send     Outbound mail failure (SPF/DKIM/DMARC/PTR audit)
#   --issue mail-recv     Inbound mail failure (MX/port/connectivity)
#   --issue web-down      Website not loading
#   --issue dns-fail      DNS resolution failure
#   --issue propagation   Propagation analysis
#   --issue wrong-domain  Wrong domain registration
#   --issue spam-received Analyse inbound spam (sender IP, SPF, blocklist)
#   --ptr                 Enhanced PTR vs A vs hostname consistency
#   --headers <file|->    Parse email headers from file or stdin (paste mode)
#   --deep                Subdomain enumeration (includes autodiscover/autoconfig)
#   --ports               Common port scan
#   --ip-reputation       Blocklist check
#   --skip-propagation    Skip propagation section
#   --guide               Print technician fix guide only
#
# EXAMPLES:
#   ./zonewalk.sh example.co.za --issue mail-send
#   ./zonewalk.sh example.co.za --issue spam-received
#   ./zonewalk.sh example.co.za --ports
#   ./zonewalk.sh example.co.za --headers headers.txt
#   ./zonewalk.sh example.co.za --headers -          # paste then Ctrl+D
#   cat headers.txt | ./zonewalk.sh example.co.za --headers -
# =========================================================

DOMAIN=$1
shift

# -- Defaults --
RUN_DEEP=false
RUN_PORTS=false
CHECK_REP=false
SKIP_PROP=false
SHOW_GUIDE=false
PTR_CONSISTENCY=false
HEADER_FILE=""
ISSUE="standard"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --deep)          RUN_DEEP=true ;;
        --ports)         RUN_PORTS=true ;;
        --ip-reputation) CHECK_REP=true ;;
        --skip-propaga*) SKIP_PROP=true ;;
        --guide)         SHOW_GUIDE=true ;;
        --ptr)           PTR_CONSISTENCY=true ;;
        --headers)       HEADER_FILE="$2"; shift ;;
        --issue)         ISSUE="$2"; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$DOMAIN" ]; then
    echo "ZONEWALK v3.1 - 1-grid L3 DNS & Mail Diagnostic"
    echo "Usage: $0 domain.co.za [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --issue <type>       mail-send | mail-recv | web-down | dns-fail | propagation | wrong-domain | spam-received"
    echo "  --ptr                Enhanced PTR vs A vs hostname consistency"
    echo "  --headers <file|->   Parse email headers from file or - for stdin (paste + Ctrl+D)"
    echo "  --deep               Subdomain enumeration"
    echo "  --ports              Common port scan"
    echo "  --ip-reputation      Blocklist check"
    echo "  --guide              Technician fix guide"
    exit 1
fi

# -- Colors --
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[1;35m'
WHITE='\033[1;37m'; GRAY='\033[0;90m'; NC='\033[0m'

OK="${GREEN}OK${NC}"; FAIL="${RED}FAIL${NC}"; WARN="${YELLOW}WARN${NC}"; INFO="${CYAN}INFO${NC}"

# -- Config --
GRID_NS=("petra" "thor" "linus" "hostserv" "lnxwzdns" "myserver" "openprovider")
GRID_NS_NAMES=(
    "petra=Windows Plesk" "thor=Linux Plesk" "linus=Linux cPanel (1)"
    "hostserv=Linux cPanel (2)" "lnxwzdns=Website Design"
    "myserver=Business VPS" "openprovider=OpenProvider (.com)"
)
COMPETITORS=(
    "cloudflare.com|Cloudflare" "hetzner.co.za|Hetzner/xneelo"
    "xneelo.co.za|xneelo" "hostafrica.com|Host Africa"
    "afrihost.com|Afrihost" "google.com|Google Workspace"
    "outlook.com|Microsoft 365" "amazon|AWS Route53" "azure|Azure DNS" "godaddy|GoDaddy"
)
COMMON_SUBDOMAINS=(www mail webmail smtp imap pop pop3 ftp cpanel whm plesk ns1 ns2 dev staging api admin portal secure vpn autodiscover autoconfig calendar contacts webdisk cpcalendars cpcontacts)
COMMON_PORTS=(21 22 25 53 80 110 143 443 465 587 993 995 2083 2087 3306 8080 8443)
PORT_NAMES=( "21=FTP" "22=SSH" "25=SMTP" "53=DNS" "80=HTTP" "110=POP3" "143=IMAP" "443=HTTPS" "465=SMTPS" "587=SMTP-Submission" "993=IMAPS" "995=POP3S" "2083=cPanel" "2087=WHM" "3306=MySQL" "8080=HTTP-Alt" "8443=HTTPS-Alt" )

# -- State --
IS_GRID=false; CURRENT_PROVIDER="Unknown / External"; HOSTING_TYPE=""
HAS_SPF=false; HAS_MC=false; HAS_DMARC=false; DMARC_WEAK=false; DMARC_POLICY=""
HAS_DKIM=false; HAS_MX=false; HAS_A=false; HAS_PTR=false; HTTP_CODE=""
ISSUES_FOUND=(); IP=""; MX_HOST=""

header()  { echo -e "\n${BLUE}==================================================${NC}"; echo -e "${WHITE}  $1${NC}"; echo -e "${BLUE}==================================================${NC}"; }
section() { echo -e "\n${MAGENTA}>> $1${NC}"; echo -e "${MAGENTA}-------------------------------------------------${NC}"; }
subsection() { echo -e "\n  ${CYAN}* $1${NC}"; }
note()    { echo -e "  ${GRAY}-> $1${NC}"; }

get_port_name() {
    local port=$1
    for entry in "${PORT_NAMES[@]}"; do
        [[ "$entry" == "${port}="* ]] && { echo "${entry#*=}"; return; }
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
        echo -e "  $FAIL No NS records found."
        ISSUES_FOUND+=("NO_NS"); return
    fi
    for ns in $NS_RECS; do echo -e "    $ns"; done

    for ns in $NS_RECS; do
        for entry in "${GRID_NS_NAMES[@]}"; do
            key="${entry%%=*}"; val="${entry#*=}"
            echo "$ns" | grep -qi "$key" && { IS_GRID=true; CURRENT_PROVIDER="1-grid"; HOSTING_TYPE="$val"; }
        done
    done

    if [ "$IS_GRID" = false ]; then
        for comp in "${COMPETITORS[@]}"; do
            iface=$(echo "$comp" | cut -d'|' -f1); name=$(echo "$comp" | cut -d'|' -f2)
            echo "$NS_RECS" | grep -qi "$iface" && CURRENT_PROVIDER="$name"
        done
    fi

    if [ "$IS_GRID" = true ]; then
        echo -e "\n  $OK Hosted with 1-grid ($HOSTING_TYPE)"
    elif echo "$NS_RECS" | grep -qi "cloudflare"; then
        echo -e "\n  $WARN DNS managed via Cloudflare (changes must be made there)"
        CURRENT_PROVIDER="Cloudflare"
    else
        echo -e "\n  $FAIL Not hosted with 1-grid - Provider: ${CURRENT_PROVIDER}"
        ISSUES_FOUND+=("NOT_GRID")
    fi
}

whois_summary() {
    section "Domain Registration & Expiry"
    command -v whois &>/dev/null || { echo -e "  $WARN whois not installed"; return; }
    local WHOIS_DATA EXPIRY REGISTRAR STATUS
    WHOIS_DATA=$(whois "$DOMAIN" 2>/dev/null)
    EXPIRY=$(echo "$WHOIS_DATA" | grep -iE "expiry|expires|Expiration Date|Expiry Date" | head -1 | sed 's/.*: //')
    REGISTRAR=$(echo "$WHOIS_DATA" | grep -iE "registrar:" | head -1 | sed 's/.*: //')
    STATUS=$(echo "$WHOIS_DATA" | grep -iE "status:" | head -3 | sed 's/.*: //' | tr '\n' ' ')
    [ -n "$REGISTRAR" ] && echo -e "  $INFO Registrar: $REGISTRAR"
    [ -n "$EXPIRY" ]    && echo -e "  $INFO Expires:   $EXPIRY"
    [ -n "$STATUS" ]    && echo -e "  $INFO Status:    $STATUS"
    if [ -n "$EXPIRY" ]; then
        local EXP_EPOCH NOW_EPOCH DAYS_LEFT
        EXP_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        if [ -n "$EXP_EPOCH" ]; then
            DAYS_LEFT=$(( (EXP_EPOCH - NOW_EPOCH) / 86400 ))
            if [ "$DAYS_LEFT" -lt 0 ]; then
                echo -e "  $FAIL DOMAIN EXPIRED ${DAYS_LEFT#-} days ago!"
                ISSUES_FOUND+=("DOMAIN_EXPIRED")
            elif [ "$DAYS_LEFT" -lt 14 ]; then
                echo -e "  $FAIL EXPIRES IN ${DAYS_LEFT} DAYS - Urgent!"
                ISSUES_FOUND+=("EXPIRY_CRITICAL")
            elif [ "$DAYS_LEFT" -lt 30 ]; then
                echo -e "  $WARN Expires in ${DAYS_LEFT} days"
            else
                echo -e "  $OK ${DAYS_LEFT} days until expiry"
            fi
        fi
    fi
}

check_a_record() {
    section "A Record & IP Info"
    A_REC=$(dig +short A "$DOMAIN" 2>/dev/null)
    if [ -z "$A_REC" ]; then
        echo -e "  $FAIL No A record found."
        ISSUES_FOUND+=("NO_A_RECORD")
    else
        HAS_A=true
        IP=$(echo "$A_REC" | head -1)
        echo -e "  $OK A record: $A_REC"
        note "Primary IP: $IP"
        local COUNT=$(echo "$A_REC" | wc -l)
        [ "$COUNT" -gt 1 ] && echo -e "  $INFO Multiple A records ($COUNT)"
    fi
}

ptr_check() {
    section "Reverse DNS (PTR)"
    local IP PTR HOST_OUT
    IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    [ -z "$IP" ] && { echo -e "  $WARN No A record - skipping PTR"; return; }
    echo -e "  $INFO PTR for $IP"

    if command -v host &>/dev/null; then
        HOST_OUT=$(host "$IP" 2>/dev/null)
        PTR=$(echo "$HOST_OUT" | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
    else
        PTR=$(dig +short -x "$IP" 2>/dev/null | grep -v "^;;\|NXDOMAIN\|SERVFAIL" | sed 's/\.$//' | head -1)
    fi

    if [ -z "$PTR" ]; then
        echo -e "  $FAIL No PTR record found"
        echo -e "  $WARN Missing PTR affects Gmail delivery"
        note "PTRs are set at IP block level - contact 1-grid support"
        HAS_PTR=false; ISSUES_FOUND+=("NO_PTR")
    else
        echo -e "  $OK PTR: $PTR"
        HAS_PTR=true
        echo "$PTR" | grep -qi "$DOMAIN" \
            && echo -e "  $OK PTR matches domain" \
            || echo -e "  $WARN PTR ($PTR) does not match $DOMAIN"
    fi
}

ptr_consistency_check() {
    section "PTR / A / Hostname Consistency Audit"
    local A_IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    [ -z "$A_IP" ] && { echo -e "  $FAIL No A record - cannot check PTR consistency"; return; }

    local PTR=$(dig +short -x "$A_IP" 2>/dev/null | sed 's/\.$//' | head -1)
    local HOSTNAME=$(dig +short PTR "$A_IP" 2>/dev/null | sed 's/\.$//' | head -1)

    echo ""
    echo "  A record:    $A_IP"
    echo "  PTR record:  ${PTR:-NONE}"
    echo "  Server host: ${HOSTNAME:-NONE}"

    if [ -z "$PTR" ]; then
        echo -e "\n  $FAIL No PTR record - Gmail/Outlook will flag as spam"
        ISSUES_FOUND+=("NO_PTR")
    else
        local REV=$(echo "$A_IP" | awk -F. '{print $4"."$3"."$2"."$1}')
        local PTR_A=$(dig +short A "$PTR" 2>/dev/null | head -1)
        echo ""
        echo "  Forward-confirm: $PTR -> $PTR_A"
        if [ "$PTR_A" = "$A_IP" ]; then
            echo -e "  $OK Forward-confirm (PTR -> A) PASS"
        else
            echo -e "  $FAIL Forward-confirm FAIL - PTR points to $PTR which resolves to $PTR_A"
            ISSUES_FOUND+=("PTR_FORWARD_FAIL")
        fi
    fi
}

check_mx() {
    section "MX Records (Mail Routing)"
    MX_RECS=$(dig +short MX "$DOMAIN" 2>/dev/null)
    if [ -z "$MX_RECS" ]; then
        echo -e "  $FAIL No MX records found"; ISSUES_FOUND+=("NO_MX")
    else
        HAS_MX=true; echo -e "  $OK MX Records:"
        while IFS= read -r mx; do
            echo -e "    $mx"
            MX_HOST=$(echo "$mx" | awk '{print $2}')
            local MX_IP=$(dig +short A "$MX_HOST" 2>/dev/null | head -1)
            [ -z "$MX_IP" ] && { echo -e "    $FAIL MX host $MX_HOST does not resolve!"; ISSUES_FOUND+=("MX_NO_RESOLVE"); }
        done <<< "$MX_RECS"
    fi
}

check_mail_auth() {
    section "Mail Authentication (SPF / DKIM / DMARC)"

    subsection "SPF"
    local SPF=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i "v=spf")
    if [ -z "$SPF" ]; then
        echo -e "  $FAIL No SPF record found"
        note "Fix: v=spf1 a mx include:relay.mailchannels.net ~all"
        ISSUES_FOUND+=("NO_SPF")
    else
        HAS_SPF=true; echo -e "  $OK $SPF"
        echo "$SPF" | grep -qi "mailchannels" \
            && { HAS_MC=true; echo -e "  $OK MailChannels authorised"; } \
            || { echo -e "  $FAIL MailChannels NOT in SPF"; ISSUES_FOUND+=("NO_MAILCHANNELS"); }
        local LOOKUP_COUNT=$(echo "$SPF" | grep -o "include:" | wc -l)
        [ "$LOOKUP_COUNT" -gt 8 ] && { echo -e "  $WARN SPF lookups >8 - risk of PermError"; ISSUES_FOUND+=("SPF_TOO_MANY_LOOKUPS"); }
    fi

    subsection "DKIM"
    local DKIM_FOUND=false
    for selector in default selector1 selector2 google mail dkim k1 zoho s1 s2 smtp email mimecast; do
        local RESULT=$(dig +short TXT "${selector}._domainkey.${DOMAIN}" 2>/dev/null)
        if [ -n "$RESULT" ]; then
            DKIM_FOUND=true; HAS_DKIM=true
            echo -e "  $OK DKIM found (selector: $selector)"
            local KEY_LEN=$(echo "$RESULT" | grep -oP 'p=\K[^"]+' | head -c 80)
            echo "    Key: ${KEY_LEN}..."
            break
        fi
    done
    [ "$DKIM_FOUND" = false ] && { echo -e "  $FAIL No DKIM record found"; ISSUES_FOUND+=("NO_DKIM"); }

    subsection "DMARC"
    local DMARC=$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | tr -d '"')
    if [ -z "$DMARC" ]; then
        echo -e "  $FAIL No DMARC record found"
        note "Fix: v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN"
        HAS_DMARC=false; DMARC_WEAK=true; ISSUES_FOUND+=("NO_DMARC")
    else
        HAS_DMARC=true; echo -e "  $OK $DMARC"
        local DMARC_POLICY=$(echo "$DMARC" | grep -oP 'p=\K[^;]+' | tr -d ' ' | cut -d';' -f1)
        case "$DMARC_POLICY" in
            reject)    echo -e "  $OK Policy: REJECT (strongest)" ;;
            quarantine) echo -e "  Policy: QUARANTINE" ;;
            none)
                DMARC_WEAK=true
                echo -e "  $FAIL Policy: NONE - no enforcement"
                ISSUES_FOUND+=("DMARC_NONE")
                ;;
        esac
        echo "$DMARC" | grep -qi "rua=" \
            && echo -e "  $INFO Reports: $(echo "$DMARC" | grep -oP 'rua=\K[^;]+')" \
            || echo -e "  $WARN No rua tag - no DMARC reports"
    fi
}

check_soa() {
    section "SOA Record (Zone Health)"
    local SOA=$(dig +short SOA "$DOMAIN" 2>/dev/null)
    [ -z "$SOA" ] && { echo -e "  $FAIL No SOA record - zone may be broken"; ISSUES_FOUND+=("NO_SOA"); return; }
    echo -e "  $OK SOA: $SOA"
    local SERIAL=$(echo "$SOA" | awk '{print $3}')
    local REFRESH=$(echo "$SOA" | awk '{print $4}')
    local RETRY=$(echo "$SOA" | awk '{print $5}')
    local EXPIRE=$(echo "$SOA" | awk '{print $6}')
    local TTL=$(echo "$SOA" | awk '{print $7}')
    note "Serial: $SERIAL  Refresh: ${REFRESH}s  Retry: ${RETRY}s  Expire: ${EXPIRE}s  Min-TTL: ${TTL}s"
}

check_ns_port53() {
    section "DNS Port 53"
    local NS_IP=$(dig +short NS "$DOMAIN" 2>/dev/null | head -1 | xargs dig +short A 2>/dev/null | head -1)
    [ -z "$NS_IP" ] && return
    (echo >/dev/tcp/"$NS_IP"/53) 2>/dev/null \
        && echo -e "  $OK Port 53 open on $NS_IP" \
        || { echo -e "  $FAIL Port 53 closed on $NS_IP"; ISSUES_FOUND+=("PORT53_CLOSED"); }
}

check_web() {
    section "Web / HTTP Check"
    command -v curl &>/dev/null || { echo -e "  $WARN curl not installed"; return; }
    for proto in "http" "https"; do
        local CODE=$(curl -o /dev/null -s -w "%{http_code}" "$proto://$DOMAIN" --max-time 8 -L 2>/dev/null)
        case "$CODE" in
            200) echo -e "  $OK $proto://$DOMAIN -> HTTP $CODE" ;;
            301|302) echo -e "  $INFO $proto -> HTTP $CODE Redirect" ;;
            403) echo -e "  $WARN $proto -> HTTP 403 Forbidden" ;;
            404) echo -e "  $WARN $proto -> HTTP 404"; ISSUES_FOUND+=("HTTP_404") ;;
            500|502|503) echo -e "  $FAIL $proto -> HTTP $CODE Server Error"; ISSUES_FOUND+=("HTTP_5XX") ;;
            000) echo -e "  $FAIL $proto -> No response"; ISSUES_FOUND+=("HTTP_NO_RESPONSE") ;;
            *) echo -e "  $WARN $proto -> HTTP $CODE" ;;
        esac
        HTTP_CODE=$CODE
    done
    local SSL_EXPIRY=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | grep notAfter | sed 's/notAfter=//')
    if [ -n "$SSL_EXPIRY" ]; then
        local SSL_EPOCH=$(date -d "$SSL_EXPIRY" +%s 2>/dev/null)
        local NOW_EPOCH=$(date +%s)
        if [ -n "$SSL_EPOCH" ]; then
            local SSL_DAYS=$(( (SSL_EPOCH - NOW_EPOCH) / 86400 ))
            [ "$SSL_DAYS" -lt 0 ]  && { echo -e "  $FAIL SSL EXPIRED"; ISSUES_FOUND+=("SSL_EXPIRED"); }
            [ "$SSL_DAYS" -lt 14 ] && [ "$SSL_DAYS" -ge 0 ] && { echo -e "  $FAIL SSL expires in $SSL_DAYS days"; ISSUES_FOUND+=("SSL_EXPIRY_CRITICAL"); }
            [ "$SSL_DAYS" -ge 14 ] && [ "$SSL_DAYS" -lt 30 ] && echo -e "  $WARN SSL expires in $SSL_DAYS days"
            [ "$SSL_DAYS" -ge 30 ] && echo -e "  $OK SSL valid for $SSL_DAYS days"
        fi
    fi
}

ip_reputation_check() {
    section "IP Reputation & Blocklist Check"
    local IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
    [ -z "$IP" ] && { echo -e "  $WARN No A record"; return; }
    echo -e "  $INFO IP: $IP"
    local REV=$(echo "$IP" | awk -F. '{print $4"."$3"."$2"."$1}')
    local BLOCKED=false
    for entry in "zen.spamhaus.org|Spamhaus ZEN" "bl.spamcop.net|SpamCop" "dnsbl.sorbs.net|SORBS" "b.barracudacentral.org|Barracuda" "dnsbl-1.uceprotect.net|UCEProtect L1" "psbl.surriel.com|PSBL"; do
        local bl=$(echo "$entry" | cut -d'|' -f1)
        local name=$(echo "$entry" | cut -d'|' -f2)
        local RESULT=$(dig +short "${REV}.${bl}" 2>/dev/null)
        [ -n "$RESULT" ] && [ "$RESULT" != "127.255.255.255" ] \
            && { echo -e "  $FAIL LISTED on $name"; BLOCKED=true; ISSUES_FOUND+=("IP_BLOCKED_$name"); } \
            || echo -e "  $OK Clean on $name"
    done
    [ "$BLOCKED" = true ] && echo -e "\n  $WARN Delist at: https://www.spamhaus.org/lookup/"
}

subdomain_enum() {
    section "Subdomain Enumeration"
    echo -e "  Checking ${#COMMON_SUBDOMAINS[@]} subdomains...\n"
    local FOUND_COUNT=0
    for sub in "${COMMON_SUBDOMAINS[@]}"; do
        local TARGET="${sub}.${DOMAIN}"
        local IP=$(dig +short A "$TARGET" 2>/dev/null | head -1)
        local CNAME=$(dig +short CNAME "$TARGET" 2>/dev/null | head -1)
        [ -n "$IP" ] && { echo -e "  $OK $TARGET -> $IP"; FOUND_COUNT=$((FOUND_COUNT+1)); }
        [ -n "$CNAME" ] && [ -z "$IP" ] && { echo -e "  $INFO $TARGET -> CNAME $CNAME"; FOUND_COUNT=$((FOUND_COUNT+1)); }
    done
    [ "$FOUND_COUNT" -eq 0 ] && echo -e "  $INFO No common subdomains found"
    echo -e "\n  $FOUND_COUNT subdomain(s) found"
}

port_scan() {
    section "Port Scan"
    echo -e "  Scanning ${#COMMON_PORTS[@]} ports...\n"
    for P in "${COMMON_PORTS[@]}"; do
        local PNAME=$(get_port_name "$P")
        if nc -zw2 "$DOMAIN" "$P" 2>/dev/null; then
            echo -e "  $OK Port $P ($PNAME): OPEN"
        else
            echo -e "  ${GRAY}Port $P ($PNAME): closed${NC}"
        fi
    done
}

check_smtp_ports() {
    subsection "SMTP Port Check"
    local MX_HOST=$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n | head -1 | awk '{print $2}')
    [ -z "$MX_HOST" ] && MX_HOST="mail.$DOMAIN"
    for port in 25 465 587; do
        (echo >/dev/tcp/"$MX_HOST"/"$port") 2>/dev/null \
            && echo -e "  $OK Port $port OPEN on $MX_HOST" \
            || echo -e "  $WARN Port $port closed on $MX_HOST"
    done
}

check_all_txt() {
    section "All TXT Records"
    local TXT_RECS=$(dig +short TXT "$DOMAIN" 2>/dev/null)
    [ -z "$TXT_RECS" ] && { echo -e "  $WARN No TXT records"; return; }
    echo "$TXT_RECS" | while IFS= read -r line; do echo "  $line"; done
}

# =========================================================
# PROPAGATION TABLE (shows actual IPs per resolver)
# =========================================================

propagation_info() {
    section "Global DNS Propagation (A Record)"
    local EXPECTED=$(dig +short A "$DOMAIN" | head -1)
    [ -z "$EXPECTED" ] && { echo -e "  $FAIL No A record found"; return; }

    echo -e "  Expected: ${WHITE}$EXPECTED${NC} (authoritative)"
    echo ""
    printf "${WHITE}%-24s %-15s %-15s %s${NC}\n" "Resolver" "IP" "Expected" "Status"
    echo -e "${GRAY}----------------------------------------------------------------------${NC}"

    local RESOLVERS=(
        "Google|8.8.8.8"
        "Cloudflare|1.1.1.1"
        "Comcast (US)|75.75.75.75"
        "OpenDNS (EU)|208.67.220.220"
        "Yandex (RU)|77.88.8.8"
        "Alibaba (AS)|223.5.5.5"
        "Liquid ZA|154.0.1.1"
        "Telkom ZA|196.25.1.1"
        "Google (SA)|8.8.4.4"
        "Telstra (AU)|139.130.4.4"
    )

    local PROPAGATED=true
    for line in "${RESOLVERS[@]}"; do
        local NAME=$(echo "$line" | cut -d'|' -f1)
        local RIP=$(echo "$line" | cut -d'|' -f2)
        local LOOKUP=$(dig @$RIP +short A "$DOMAIN" +time=1 +tries=1 | head -1)

        if [ "$LOOKUP" = "$EXPECTED" ]; then
            printf "%-24s %-15s %-15s %b\n" "$NAME" "$RIP" "$LOOKUP" "${GREEN}MATCH${NC}"
        elif [ -z "$LOOKUP" ]; then
            printf "%-24s %-15s %-15s %b\n" "$NAME" "$RIP" "-" "${RED}NO RECORD${NC}"
            PROPAGATED=false
        else
            printf "%-24s %-15s %-15s %b\n" "$NAME" "$RIP" "$LOOKUP" "${RED}MISMATCH${NC}"
            PROPAGATED=false
        fi
    done

    echo ""
    [ "$PROPAGATED" = true ] && echo -e "  $OK Fully propagated - all resolvers return expected IP" \
        || echo -e "  $WARN Still propagating - some resolvers differ from authoritative"

    echo ""
    section "Propagation Times Reference"
    echo "  Record          Min         Max         Notes"
    echo "  --------------------------------------------------------------"
    echo "  Nameserver      12 hrs      48 hrs      ISPs cache aggressively"
    echo "  MX Record       1 hr        24 hrs      Affects inbound email"
    echo "  A/CNAME/TXT     15 min      4 hrs       Depends on TTL setting"
    echo "  DMARC           15 min      4 hrs       Check dmarcian.com"
    echo ""
    echo -e "  $INFO Track: https://dnschecker.org/"
}

# =========================================================
# EMAIL HEADER ANALYZER (enhanced)
# =========================================================

mail_header_analysis() {
    header "EMAIL HEADER ANALYSIS"
    local HEADER_FILE="${1:--}"
    local INPUT=""

    if [ "$HEADER_FILE" = "-" ]; then
        if [ -t 0 ]; then
            echo -e "  ${CYAN}Paste email headers below, then press Ctrl+D when done:${NC}\n"
        fi
        INPUT=$(cat)
    elif [ -f "$HEADER_FILE" ]; then
        INPUT=$(cat "$HEADER_FILE")
    else
        echo -e "  $FAIL Header file not found: $HEADER_FILE"
        return
    fi

    [ -z "$INPUT" ] && { echo -e "  $FAIL No header input received"; return; }
    echo -e "  $INFO Parsing email headers...\n"

    # -- Envelope --
    local FROM=$(echo "$INPUT" | grep -i "^From:" | head -1 | sed 's/^From: //I')
    local TO=$(echo "$INPUT" | grep -i "^To:" | head -1 | sed 's/^To: //I')
    local SUBJECT=$(echo "$INPUT" | grep -i "^Subject:" | head -1 | sed 's/^Subject: //I')
    local DATE=$(echo "$INPUT" | grep -i "^Date:" | head -1 | sed 's/^Date: //I')
    local RETURN_PATH=$(echo "$INPUT" | grep -i "^Return-Path:" | head -1 | sed 's/^Return-Path: //I' | tr -d '<>')
    local REPLY_TO=$(echo "$INPUT" | grep -i "^Reply-To:" | head -1 | sed 's/^Reply-To: //I')
    local XMAILER=$(echo "$INPUT" | grep -iE "^X-Mailer:|^User-Agent:" | head -1)

    echo -e "  ${WHITE}Envelope:${NC}"
    echo "    From:         ${FROM:-N/A}"
    echo "    Return-Path:  ${RETURN_PATH:-N/A}"
    [ -n "$REPLY_TO" ] && echo "    Reply-To:     $REPLY_TO"
    echo "    To:           ${TO:-N/A}"
    echo "    Subject:      ${SUBJECT:-N/A}"
    echo "    Date:         ${DATE:-N/A}"
    [ -n "$XMAILER" ] && echo "    Sender Agent: $XMAILER"

    # -- Return-Path vs From mismatch (spoofing indicator) --
    echo ""
    echo -e "  ${WHITE}Spoofing Checks:${NC}"
    local FROM_DOMAIN=$(echo "$FROM" | grep -oP '@\K[^>]+' | head -1 | tr -d ' ')
    local RP_DOMAIN=$(echo "$RETURN_PATH" | grep -oP '@\K[^>]+' | head -1 | tr -d ' ')
    if [ -n "$FROM_DOMAIN" ] && [ -n "$RP_DOMAIN" ]; then
        if [ "$FROM_DOMAIN" = "$RP_DOMAIN" ]; then
            echo -e "  $OK From domain matches Return-Path ($FROM_DOMAIN)"
        else
            echo -e "  $FAIL From/Return-Path MISMATCH: From=$FROM_DOMAIN  Return-Path=$RP_DOMAIN"
            echo -e "  $WARN Possible spoofing or third-party sender"
        fi
    fi
    if [ -n "$REPLY_TO" ]; then
        local RT_DOMAIN=$(echo "$REPLY_TO" | grep -oP '@\K[^>]+' | head -1 | tr -d ' ')
        [ -n "$RT_DOMAIN" ] && [ "$RT_DOMAIN" != "$FROM_DOMAIN" ] \
            && echo -e "  $WARN Reply-To domain ($RT_DOMAIN) differs from From domain ($FROM_DOMAIN) - phishing indicator"
    fi

    # -- Authentication Results --
    echo ""
    echo -e "  ${WHITE}Authentication Results:${NC}"
    local AUTH=$(echo "$INPUT" | grep -i "Authentication-Results:" | head -5)
    if [ -n "$AUTH" ]; then
        local SPF_RESULT=$(echo "$AUTH" | grep -oP 'spf=\K\S+' | head -1)
        local DKIM_RESULT=$(echo "$AUTH" | grep -oP 'dkim=\K\S+' | head -1)
        local DMARC_RESULT=$(echo "$AUTH" | grep -oP 'dmarc=\K\S+' | head -1)
        local ARC_RESULT=$(echo "$INPUT" | grep -i "ARC-Authentication-Results:" | head -1 | grep -oP 'dmarc=\K\S+' | head -1)

        [ "$SPF_RESULT"   = "pass" ] && echo -e "  $OK SPF:   PASS"   || echo -e "  $FAIL SPF:   ${SPF_RESULT:-not checked}"
        [ "$DKIM_RESULT"  = "pass" ] && echo -e "  $OK DKIM:  PASS"   || echo -e "  $FAIL DKIM:  ${DKIM_RESULT:-not checked}"
        [ "$DMARC_RESULT" = "pass" ] && echo -e "  $OK DMARC: PASS"   || echo -e "  $FAIL DMARC: ${DMARC_RESULT:-not checked}"
        [ -n "$ARC_RESULT" ] && echo -e "  $INFO ARC:   $ARC_RESULT (forwarded mail)"

        # DKIM domain alignment
        local DKIM_DOMAIN=$(echo "$INPUT" | grep -i "DKIM-Signature:" | grep -oP 'd=\K[^;]+' | head -1 | tr -d ' ')
        if [ -n "$DKIM_DOMAIN" ] && [ -n "$FROM_DOMAIN" ]; then
            [ "$DKIM_DOMAIN" = "$FROM_DOMAIN" ] \
                && echo -e "  $OK DKIM domain aligned ($DKIM_DOMAIN)" \
                || echo -e "  $WARN DKIM domain ($DKIM_DOMAIN) != From domain ($FROM_DOMAIN) - DMARC alignment fail"
        fi
    else
        echo -e "  $WARN No Authentication-Results header found"
    fi

    # -- X-Spam Score --
    echo ""
    echo -e "  ${WHITE}Spam Score:${NC}"
    local SPAM_STATUS=$(echo "$INPUT" | grep -i "^X-Spam-Status:" | head -1 | sed 's/^X-Spam-Status: //I')
    local SPAM_SCORE=$(echo "$INPUT" | grep -i "^X-Spam-Score:" | head -1 | sed 's/^X-Spam-Score: //I')
    local SPAM_LEVEL=$(echo "$INPUT" | grep -i "^X-Spam-Level:" | head -1 | sed 's/^X-Spam-Level: //I')
    [ -n "$SPAM_STATUS" ] && echo "    Status: $SPAM_STATUS"
    [ -n "$SPAM_SCORE"  ] && echo "    Score:  $SPAM_SCORE"
    [ -n "$SPAM_LEVEL"  ] && echo "    Level:  $SPAM_LEVEL"
    [ -z "$SPAM_STATUS$SPAM_SCORE$SPAM_LEVEL" ] && echo "    No X-Spam headers found"

    # -- Originating IP (bottom-most Received header = true origin) --
    echo ""
    echo -e "  ${WHITE}Originating IP:${NC}"
    local ORIG_IP=$(echo "$INPUT" | grep -i "^Received:" | tail -1 | grep -oP '\[(\d{1,3}\.){3}\d{1,3}\]' | tr -d '[]' | head -1)
    [ -z "$ORIG_IP" ] && ORIG_IP=$(echo "$INPUT" | grep -i "^Received:" | tail -1 | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
    if [ -n "$ORIG_IP" ]; then
        echo "    IP: $ORIG_IP"
        # PTR of originating IP
        local ORIG_PTR=$(dig +short -x "$ORIG_IP" 2>/dev/null | sed 's/\.$//' | head -1)
        [ -n "$ORIG_PTR" ] && echo "    PTR: $ORIG_PTR" || echo -e "    $WARN No PTR for originating IP"
        # Quick blocklist check on originating IP
        local ORIG_REV=$(echo "$ORIG_IP" | awk -F. '{print $4"."$3"."$2"."$1}')
        local ORIG_LISTED=$(dig +short "${ORIG_REV}.zen.spamhaus.org" 2>/dev/null | grep -v "^;")
        [ -n "$ORIG_LISTED" ] && echo -e "    $FAIL Originating IP listed on Spamhaus ZEN!" \
            || echo -e "    $OK Originating IP clean on Spamhaus ZEN"
    else
        echo "    Could not extract originating IP"
    fi

    # -- Hop-by-hop trace with delay calculation --
    echo ""
    echo -e "  ${WHITE}Hop-by-Hop Trace (newest first → oldest last):${NC}"
    local RECEIVED_LINES=()
    while IFS= read -r line; do
        RECEIVED_LINES+=("$line")
    done < <(echo "$INPUT" | grep -i "^Received:")

    local TOTAL_HOPS=${#RECEIVED_LINES[@]}
    local PREV_EPOCH=""
    for (( i=0; i<TOTAL_HOPS; i++ )); do
        local line="${RECEIVED_LINES[$i]}"
        local HOP_NUM=$((i+1))
        local HOP_FROM=$(echo "$line" | grep -oP 'from\s+\K\S+' | head -1)
        local HOP_BY=$(echo "$line" | grep -oP '\bby\s+\K\S+' | head -1)
        local HOP_WITH=$(echo "$line" | grep -oP '\bwith\s+\K\S+' | head -1)
        local HOP_TIME=$(echo "$line" | grep -oP ';\s+\K.+' | head -1 | xargs)
        local DELAY_STR=""
        if [ -n "$HOP_TIME" ]; then
            local HOP_EPOCH=$(date -d "$HOP_TIME" +%s 2>/dev/null)
            if [ -n "$HOP_EPOCH" ] && [ -n "$PREV_EPOCH" ]; then
                local DIFF=$(( PREV_EPOCH - HOP_EPOCH ))
                [ "$DIFF" -lt 0 ] && DIFF=0
                if [ "$DIFF" -ge 60 ]; then
                    DELAY_STR=" ${YELLOW}[+$((DIFF/60))m $((DIFF%60))s delay]${NC}"
                else
                    DELAY_STR=" ${GRAY}[+${DIFF}s]${NC}"
                fi
            fi
            PREV_EPOCH="$HOP_EPOCH"
        fi
        echo -e "    Hop $HOP_NUM: ${HOP_FROM:-?} → ${HOP_BY:-?} (${HOP_WITH:-?})${DELAY_STR}"
        [ -n "$HOP_TIME" ] && echo -e "           ${GRAY}$HOP_TIME${NC}"
    done
    echo -e "    $TOTAL_HOPS hop(s) total"

    # -- Block reason identification --
    echo ""
    echo -e "  ${WHITE}Block / Rejection Analysis:${NC}"
    local REJECT_REASON=""
    echo "$INPUT" | grep -qi "550-5\.7\.1"    && REJECT_REASON="Gmail 550-5.7.1: Unauthenticated - SPF/DKIM/DMARC failure"
    echo "$INPUT" | grep -qi "550-5\.7\.26"   && REJECT_REASON="Gmail 550-5.7.26: ARC authentication failed (forwarded mail)"
    echo "$INPUT" | grep -qi "4\.7\.26"       && REJECT_REASON="Gmail 4.7.26: Unauthenticated email from domain"
    echo "$INPUT" | grep -qi "spf=hardfail\|spf=fail" && REJECT_REASON="SPF hardfail: Sender IP not authorised for this domain"
    echo "$INPUT" | grep -qi "dkim=fail"      && REJECT_REASON="DKIM fail: Signature invalid or domain mismatch"
    echo "$INPUT" | grep -qi "dmarc=fail"     && REJECT_REASON="DMARC fail: Neither SPF nor DKIM passed alignment"
    echo "$INPUT" | grep -qi "550.*spam\|spam.*550" && REJECT_REASON="550 SPAM: Content or IP reputation flagged"
    echo "$INPUT" | grep -qi "554.*reject\|554.*denied" && REJECT_REASON="554 Rejected: Server policy or blocklist match"
    echo "$INPUT" | grep -qi "451.*temporary\|451.*try again" && REJECT_REASON="451 Temp fail: Recipient server busy or rate-limited"

    if [ -n "$REJECT_REASON" ]; then
        echo -e "  $FAIL $REJECT_REASON"
    else
        echo -e "  $INFO No explicit rejection pattern detected in headers"
    fi
}

# =========================================================
# REMOTE SSH CHECKS  (removed - not permitted)
# =========================================================

# =========================================================
# ISSUE DIAGNOSTIC
# =========================================================

issue_diagnostic() {
    header "ISSUE DIAGNOSTIC: ${ISSUE^^}"
    case $ISSUE in
        mail-send)
            section "Outbound Mail Diagnosis"
            check_mail_auth; check_smtp_ports; ip_reputation_check; ptr_check
            echo ""
            echo "Root causes:"
            [ "$HAS_SPF" = false ]  && echo "  $FAIL No SPF record"
            [ "$HAS_MC" = false ]   && echo "  $FAIL MailChannels not in SPF"
            [ "$HAS_DKIM" = false ] && echo "  $FAIL No DKIM signing"
            [ "$DMARC_WEAK" = true ] && echo "  $FAIL DMARC weak or missing"
            [ "$HAS_PTR" = false ]  && echo "  $WARN No PTR record"
            [ "$HAS_SPF" = true ] && [ "$HAS_DKIM" = true ] && [ "$DMARC_WEAK" = false ] \
                && echo -e "  $OK SPF/DKIM/DMARC all pass"
            ;;
        mail-recv)
            section "Inbound Mail Diagnosis"; check_mx; check_smtp_ports
            echo ""; echo "Checklist:"
            note "1. MX records correct?"; note "2. Port 25 open?"
            note "3. Mailbox quota full?"; note "4. Spam folder?"
            note "5. Client settings: mail.$DOMAIN port 993/465"
            ;;
        web-down)
            section "Website Down Diagnosis"; check_a_record; check_web
            echo ""; echo "Checklist:"
            note "1. A record correct?"; note "2. Web server running?"
            note "3. Firewall port 80/443?"; note "4. Domain expired?"
            note "5. Check error_log"
            ;;
        dns-fail)
            section "DNS Failure Diagnosis"; check_soa; check_ns_port53
            echo ""; echo "Checklist:"
            note "1. NS records exist?"; note "2. named running?"
            note "3. Port 53 open?"; note "4. Zone file valid?"
            ;;
        propagation) propagation_info ;;
        wrong-domain)
            section "Wrong Domain Registration"
            echo "  Registry restriction: domain names cannot be changed after registration."
            echo "  Options: 1) Register correct domain  2) Let incorrect domain expire"
            ;;
        spam-received)
            section "Inbound Spam Analysis"
            echo -e "  $INFO Paste the full email headers when prompted.\n"
            mail_header_analysis "-"
            ;;
    esac
}

# =========================================================
# ISSUE SUMMARY
# =========================================================

print_issue_summary() {
    [ ${#ISSUES_FOUND[@]} -eq 0 ] && {
        header "ALL CHECKS PASSED - No issues"
        return
    }
    header "ISSUES SUMMARY (${#ISSUES_FOUND[@]} found)"
    for issue in "${ISSUES_FOUND[@]}"; do
        case $issue in
            NO_NS)              echo "  $FAIL No NS records" ;;
            NOT_GRID)           echo "  $WARN External provider: $CURRENT_PROVIDER" ;;
            NO_A_RECORD)        echo "  $FAIL No A record" ;;
            NO_MX)              echo "  $FAIL No MX records" ;;
            MX_NO_RESOLVE)      echo "  $FAIL MX host does not resolve" ;;
            NO_SPF)             echo "  $FAIL Missing SPF record" ;;
            NO_MAILCHANNELS)    echo "  $FAIL MailChannels not in SPF" ;;
            SPF_TOO_MANY_LOOKUPS) echo "  $WARN SPF too many lookups" ;;
            NO_DKIM)            echo "  $FAIL No DKIM record" ;;
            NO_DMARC)           echo "  $FAIL Missing DMARC" ;;
            DMARC_NONE)         echo "  $WARN DMARC policy is 'none'" ;;
            NO_PTR)             echo "  $WARN No PTR record" ;;
            PTR_FORWARD_FAIL)   echo "  $FAIL PTR forward-confirm failed" ;;
            NO_SOA)             echo "  $FAIL No SOA record" ;;
            PORT53_CLOSED)      echo "  $FAIL Port 53 closed" ;;
            HTTP_404)           echo "  $WARN Website 404" ;;
            HTTP_5XX)           echo "  $FAIL Website 5xx error" ;;
            HTTP_NO_RESPONSE)   echo "  $FAIL Website not responding" ;;
            SSL_EXPIRED)        echo "  $FAIL SSL EXPIRED" ;;
            SSL_EXPIRY_CRITICAL) echo "  $FAIL SSL expires <14 days" ;;
            DOMAIN_EXPIRED)     echo "  $FAIL DOMAIN EXPIRED" ;;
            EXPIRY_CRITICAL)    echo "  $FAIL Domain expires <14 days" ;;
            IP_BLOCKED*)        echo "  $FAIL IP on spam blocklist" ;;
        esac
    done
}

# =========================================================
# TECHNICIAN FIX GUIDE
# =========================================================

technician_guide() {
    header "TECHNICIAN FIX GUIDE"
    [ ${#ISSUES_FOUND[@]} -eq 0 ] && { echo "  No issues to fix"; return; }
    for issue in "${ISSUES_FOUND[@]}"; do
        echo ""
        echo "======================================================================"
        case $issue in
            NO_A_RECORD)
                echo "FIX: A Record"
                echo "cPanel: Domains -> Zone Editor -> Manage -> + Add Record -> Type A"
                echo "  Name: @   Record: <IP>"
                echo "Plesk: Websites & Domains -> DNS Settings -> + Add Record -> Type A"
                echo "  Domain: ${DOMAIN}.   IP: <IP>"
                ;;
            NO_SPF|NO_MAILCHANNELS)
                echo "FIX: SPF Record"
                echo "Add: v=spf1 a mx include:relay.mailchannels.net ~all"
                echo "cPanel Zone Editor -> Type TXT, Name: ${DOMAIN}."
                echo "Plesk DNS Settings -> Type TXT, Name: ${DOMAIN}."
                ;;
            NO_DKIM)
                echo "FIX: DKIM"
                echo "cPanel: Email Deliverability -> Manage -> Enable DKIM"
                echo "Plesk: Websites & Domains -> Mail Settings -> Use DKIM"
                ;;
            NO_DMARC|DMARC_NONE)
                echo "FIX: DMARC"
                echo "Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}"
                echo "cPanel: Zone Editor -> Type TXT, Name: _dmarc"
                echo "Plesk: DNS Settings -> Type TXT, Name: _dmarc.${DOMAIN}."
                ;;
            NO_MX)
                echo "FIX: MX Records"
                echo "cPanel: Zone Editor -> + Add Record -> Type MX"
                echo "  Priority: 0   Destination: mail.${DOMAIN}."
                echo "  Also add A record: mail -> <IP>"
                echo "Plesk: DNS Settings -> + Add Record -> Type MX"
                ;;
            NO_PTR)
                echo "FIX: PTR Reverse DNS"
                echo "PTR is set at IP level - open ticket with 1-grid support"
                echo "Request: Set PTR for <IP> to mail.${DOMAIN}"
                ;;
            PTR_FORWARD_FAIL)
                echo "FIX: PTR Forward-Confirm"
                echo "PTR points to a hostname that does not resolve back to the IP."
                echo "Fix: Ensure PTR hostname has an A record pointing to the same IP."
                ;;
            SSL_EXPIRED|SSL_EXPIRY_CRITICAL)
                echo "FIX: SSL Certificate"
                echo "cPanel: SSL/TLS Status -> Run AutoSSL"
                echo "Plesk: Websites & Domains -> SSL/TLS Certificates -> Let's Encrypt -> Issue"
                ;;
            HTTP_NO_RESPONSE)
                echo "FIX: Web Server Down"
                echo "cPanel: systemctl restart httpd"
                echo "Plesk: Tools & Settings -> Services -> Restart nginx/apache"
                ;;
            DOMAIN_EXPIRED|EXPIRY_CRITICAL)
                echo "FIX: Domain Renewal"
                echo "https://my.1-grid.com -> Domains -> My Domains -> Renew"
                ;;
            NO_SOA|PORT53_CLOSED)
                echo "FIX: DNS Zone"
                echo "SSH: systemctl restart named; firewall-cmd --add-service=dns --permanent"
                echo "cPanel: Zone Editor -> check zone exists"
                echo "Plesk: DNS Settings -> check SOA"
                ;;
            IP_BLOCKED*)
                echo "FIX: IP Blocklisted"
                echo "1. Check for compromised accounts"
                echo "2. Change all email passwords"
                echo "3. Delist: https://www.spamhaus.org/lookup/"
                ;;
            NOT_GRID)
                echo "NOTE: External DNS - ${CURRENT_PROVIDER}"
                [ "$CURRENT_PROVIDER" = "Cloudflare" ] && echo "Cloudflare: https://dash.cloudflare.com/ -> DNS"
                ;;
        esac
    done
    echo ""
    echo "Quick Reference:"
    echo "  cPanel DNS path: Domains -> Zone Editor -> Manage"
    echo "  Plesk DNS path:  Websites & Domains -> DNS Settings"
}

# =========================================================
# AUTO TICKET RESPONSE (diagnosis only, no fluff)
# =========================================================

auto_ticket_response() {
    header "DIAGNOSIS SUMMARY"
    echo "Domain: ${DOMAIN}"
    echo "Date:   $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Issue:  ${ISSUE^}"
    echo "Server: ${CURRENT_PROVIDER}${HOSTING_TYPE:+ ($HOSTING_TYPE)}"
    echo ""

    [ ${#ISSUES_FOUND[@]} -eq 0 ] && {
        echo "No issues detected. All records appear correct."
        return
    }

    echo "Issues Found:"
    for issue in "${ISSUES_FOUND[@]}"; do
        case $issue in
            NO_NS)              echo "  $FAIL Nameserver records missing - domain not resolvable" ;;
            NOT_GRID)           echo "  $WARN External provider: $CURRENT_PROVIDER" ;;
            NO_A_RECORD)        echo "  $FAIL No A record - website will not load" ;;
            NO_MX)              echo "  $FAIL No MX records - inbound email fails" ;;
            MX_NO_RESOLVE)      echo "  $FAIL MX hostname does not resolve to an IP" ;;
            NO_SPF)             echo "  $FAIL SPF missing - outbound mail may be rejected" ;;
            NO_MAILCHANNELS)    echo "  $FAIL MailChannels not authorised in SPF" ;;
            SPF_TOO_MANY_LOOKUPS) echo "  $WARN SPF exceeds 10-lookup limit" ;;
            NO_DKIM)            echo "  $FAIL DKIM not configured - email not signed" ;;
            NO_DMARC)           echo "  $FAIL DMARC missing - Gmail/Yahoo may throttle" ;;
            DMARC_NONE)         echo "  $WARN DMARC policy is 'none' - no enforcement" ;;
            NO_PTR)             echo "  $WARN No PTR record - affects Gmail delivery" ;;
            PTR_FORWARD_FAIL)   echo "  $FAIL PTR forward-confirm broken" ;;
            NO_SOA)             echo "  $FAIL DNS zone missing or corrupt" ;;
            PORT53_CLOSED)      echo "  $FAIL Port 53 closed - nameserver unreachable" ;;
            HTTP_404)           echo "  $WARN HTTP 404 - website files missing" ;;
            HTTP_5XX)           echo "  $FAIL HTTP 5xx - server-side error" ;;
            HTTP_NO_RESPONSE)   echo "  $FAIL Website not responding" ;;
            SSL_EXPIRED)        echo "  $FAIL SSL certificate EXPIRED" ;;
            SSL_EXPIRY_CRITICAL) echo "  $FAIL SSL expiring within 14 days" ;;
            DOMAIN_EXPIRED)     echo "  $FAIL Domain has EXPIRED" ;;
            EXPIRY_CRITICAL)    echo "  $FAIL Domain expiring within 14 days" ;;
            IP_BLOCKED*)        echo "  $FAIL IP on spam blocklist - mail delivery blocked" ;;
        esac
    done

    # Action if DNS records were fixed
    local HAS_DNS=false
    for i in "${ISSUES_FOUND[@]}"; do
        case $i in NO_*|DMARC_*|SSL_*|PORT53_*|PTR_*) HAS_DNS=true ;; esac
    done
    [ "$HAS_DNS" = true ] && echo -e "\n  ${YELLOW}DNS changes made - allow propagation (up to 48h for NS, 4h for others)${NC}"
    echo -e "\n  ${CYAN}Monitor: https://dnschecker.org/${NC}"
}

# =========================================================
# MAIN EXECUTION
# =========================================================

[ -n "$HEADER_FILE" ] && { mail_header_analysis "$HEADER_FILE"; exit 0; }
[ "$PTR_CONSISTENCY" = true ] && { ptr_consistency_check; exit 0; }
[ "$SHOW_GUIDE" = true ] && {
    check_ns_and_provider; check_a_record; check_mail_auth
    technician_guide; exit 0
}

header "ZONEWALK v3.1 - $DOMAIN"
echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')  |  Issue: ${ISSUE^}"
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

[ "$ISSUE" != "standard" ] && issue_diagnostic
[ "$CHECK_REP" = true ] && ip_reputation_check
[ "$RUN_DEEP"  = true ] && subdomain_enum
[ "$RUN_PORTS" = true ] && port_scan

echo ""
print_issue_summary
echo ""
auto_ticket_response

[ ${#ISSUES_FOUND[@]} -gt 0 ] && echo -e "\n${YELLOW}Tip: Run with --guide for fix steps${NC}"
