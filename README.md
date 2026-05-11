🛡️ Zonewalk
The L3 Sysadmin’s Swiss Army Knife for cPanel & Plesk Diagnostics.

Zonewalk is a workstation-based Bash utility designed for 1-grid support engineers. It bridges the gap between external DNS lookups and internal server-side health checks, specifically targeting Gmail deliverability issues and webmail permission errors.

🚀 Features
📧 Mail Delivery (Gmail Focus)
Log Surgeon: Remotely greps exim_mainlog for a specific domain to catch Gmail 550 codes.

Authentication Audit: Verifies SPF, DKIM, and DMARC alignment.

PTR Consistency: Validates that the IP's Reverse DNS matches the Server Hostname.

🛠️ Server-Side Diagnostics
Permission Auditor: Checks /home/user/mail ownership and permissions remotely.

Quota Tracker: Verifies if mailbox failures are due to disk space or inode exhaustion.

Webmail Health: Detects locked Roundcube SQLite databases and .cagefs issues.

⚡ Automation
One-Click Pass Reset: Resets cPanel passwords via SSH using /scripts/chpass.

Smart Fix Suggestions: Outputs the exact CLI command needed to fix the detected error.

📋 Prerequisites
To run Zonewalk from your workstation, ensure you have:

SSH Key Access: Your public key should be in the authorized_keys of the target 1-grid servers.

Tools: dig, ssh, curl, and openssl (standard on Linux/macOS).

Permissions: Root or sudo access on the remote server for log grepping.

🛠️ Usage
1. Basic DNS & Auth Check
Bash
./zonewalk.sh --domain example.co.za
2. Deep Mail Trace (Remote Logs)
Bash
./zonewalk.sh --logs --domain example.co.za --server 102.x.x.x
3. Permission & Quota Audit
Bash
./zonewalk.sh --perms --user cpuser --server 102.x.x.x
4. Remote Password Reset
Bash
./zonewalk.sh --reset-pass --user cpuser --server 102.x.x.x

📁 Directory Structure
Plaintext
zonewalk/
├── zonewalk.sh        # Main Bash script
├── lib/               # Modular logic (DNS, SSH, Logs)
├── data/              # RBL lists and known error codes
└── reports/           # Saved diagnostic outputs
💡 Troubleshooting Logic
Zonewalk follows a "Chain of Trust" logic for 1-grid tickets:

Is DNS pointing to us? (Nameserver Check)

Is the mail routing correct? (Remote vs. Local)

Is Gmail rejecting us? (Log Analysis)

Can the server write the file? (Permissions/Quota)

Note: Developed for L3 support. Use with caution on production environments.
