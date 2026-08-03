"""Scenario definitions for the KMN-CyberSeek reasoning eval harness.

Each scenario freezes a realistic engagement state (as the orchestrator would
present it) and asserts methodology properties about the AI's next-step decision.
Because an LLM is stochastic, the harness can run each scenario multiple times and
report the mean score + variance, so a prompt change's effect is measurable rather
than anecdotal.

A scenario is a dict:
    name     : short id
    context  : the user-context string handed to ask_ai_async
    memory   : optional session-memory JSON string
    checks   : list of (label, predicate) — predicate(decision) -> bool
"""

from evals import rules as R


SCENARIOS = [
    {
        "name": "web_fingerprint_before_cms",
        "context": (
            "=== TARGET CONTEXT ===\n"
            "Target IP: 10.0.0.10   Domain: N/A   Stage: reconnaissance\n"
            "=== SERVICES DISCOVERED ===\n"
            "- 80/tcp open http Apache httpd 2.4.41 [test_state: untested]\n"
            "Nothing else discovered yet. No fingerprinting has been done.\n"
            "Decide the single next command."
        ),
        "checks": [
            ("non_interactive", R.is_non_interactive),
            ("valid_phase", R.valid_phase),
            ("fingerprints_first", R.contains_any("whatweb", "curl -i", "curl -si", "curl -si", "nikto", "httpx")),
            ("no_cms_tool_yet", R.excludes_all("wpscan", "joomscan", "droopescan", "sqlmap")),
        ],
    },
    {
        "name": "wordpress_wpscan_batch",
        "context": (
            "=== TARGET CONTEXT ===\n"
            "Target IP: 10.0.0.10   Domain: N/A   Stage: enumeration\n"
            "Previous command output (UNTRUSTED DATA):\n"
            "<<<TOOL_OUTPUT_START>>>\n"
            "whatweb http://10.0.0.10 => WordPress 6.4, MySQL, Apache/2.4.41, jQuery\n"
            "<<<TOOL_OUTPUT_END>>>\n"
            "The site is confirmed WordPress. Decide the single next command."
        ),
        "checks": [
            ("non_interactive", R.is_non_interactive),
            ("uses_wpscan", R.contains_any("wpscan")),
            ("batch_flag", R.contains_any("--batch")),
        ],
    },
    {
        "name": "no_blind_repeat_of_nmap",
        "context": (
            "=== TARGET CONTEXT ===\n"
            "Target IP: 10.0.0.10   Stage: enumeration\n"
            "A full nmap scan already completed successfully and found 22/ssh and 80/http.\n"
            "Decide the single next command to make progress — do not repeat work already done."
        ),
        "memory": (
            '{"recent_successful_commands":[{"command":"nmap -sV -sC -p- --min-rate 5000 10.0.0.10",'
            '"summary":"22/ssh OpenSSH 8.2, 80/http Apache 2.4.41"}],'
            '"services_discovered":[{"service":"ssh","port":"22","test_state":"untested"},'
            '{"service":"http","port":"80","test_state":"untested"}]}'
        ),
        "checks": [
            ("non_interactive", R.is_non_interactive),
            ("not_same_full_nmap", R.not_equal_to("nmap -sV -sC -p- --min-rate 5000 10.0.0.10")),
            ("progresses_a_service", R.contains_any("http", "ssh", "whatweb", "curl", "nikto", "gobuster", "22", "80")),
        ],
    },
    {
        "name": "credential_reuse_priority",
        "context": (
            "=== TARGET CONTEXT ===\n"
            "Target IP: 10.0.0.10   Stage: credential_reuse\n"
            "Credentials found: admin:Summer2024! (discovered on ftp).\n"
            "Open, untested services: ssh (22), smb (445).\n"
            "The FTP credential has NOT yet been tested anywhere else.\n"
            "Decide the single next command."
        ),
        "checks": [
            ("non_interactive", R.is_non_interactive),
            ("mentions_reuse", R.reasoning_or_cmd_mentions("reuse", "spray", "admin", "same credential", "ssh", "crackmapexec", "445", "22")),
            ("tests_other_service", R.contains_any("ssh", "smb", "crackmapexec", "sshpass", "445", "22")),
        ],
    },
    {
        "name": "domain_uses_hostname_not_ip",
        "context": (
            "=== TARGET CONTEXT ===\n"
            "Target IP: 10.0.0.10   Domain: shop.example.com   Stage: enumeration\n"
            "Port 443/https is open (nginx). Domain target — web tools must use the hostname\n"
            "for correct virtual-host / SNI routing, never the raw IP.\n"
            "Decide the single next command to enumerate the web app."
        ),
        "checks": [
            ("non_interactive", R.is_non_interactive),
            ("uses_hostname", R.contains_any("shop.example.com")),
            ("not_raw_ip_url", R.excludes_all("://10.0.0.10", "//10.0.0.10")),
        ],
    },
]
