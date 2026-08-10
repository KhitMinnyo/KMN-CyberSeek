#!/usr/bin/env python3
"""Standalone documentation server for KMN-CyberSeek.

Serves bilingual (EN / MY) documentation on port 3500.
No Streamlit dependency — runs independently from start.sh.
"""

import http.server
import os
import socketserver

DOCS_PORT = int(os.environ.get("DOCS_PORT", 3500))


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _bi(en: str, my: str) -> str:
    """Bilingual span — one shown at a time via CSS."""
    return f'<span class="en">{en}</span><span class="my">{my}</span>'


def _c(title: str, body: str, accent: str = "#4f8ef7") -> str:
    return (f'<div class="card" style="border-left-color:{accent}">'
            f'<div class="ct">{title}</div>'
            f'<div class="cb">{body}</div></div>')


def _s(text: str) -> str:
    return f'<div class="sh">{text}</div>'


def _note(text: str, cls: str = "ai") -> str:
    return f'<div class="alert {cls}">{text}</div>'


def _pre(text: str) -> str:
    return f'<pre>{text}</pre>'


def _exp(q: str, a: str) -> str:
    return (f'<details class="exp"><summary>{q}</summary>'
            f'<div class="exb">{a}</div></details>')


# ---------------------------------------------------------------------------
# Tab content
# ---------------------------------------------------------------------------

def _tab0() -> str:
    h = ""
    h += _s(_bi("Quick Start", "အမြန်စတင်နည်း"))
    h += _c(
        _bi("1. Run <code>./start.sh</code>", "1. <code>./start.sh</code> run ပါ"),
        _bi("Starts FastAPI (port 6000) and Streamlit (port 8501).",
            "FastAPI (port 6000) နှင့် Streamlit (port 8501) ကိုစတင်သည်။"),
        "#4caf50")
    h += _c(
        _bi("2. Settings &#8594; AI Configuration",
            "2. Settings &#8594; AI Configuration"),
        _bi("Connect Ollama or enter a DeepSeek API key.",
            "Ollama ချိတ်ဆက်ရန် သို့မဟုတ် DeepSeek API key ထည့်ရန်။"),
        "#4caf50")
    h += _c(
        _bi("3. Click New Session", "3. New Session နှိပ်ပါ"),
        _bi("Enter a target IP or domain and confirm authorization.",
            "ပစ်မှတ် IP သို့မဟုတ် domain ထည့်ပြီး authorization အတည်ပြုပါ။"),
        "#4caf50")
    h += _c(
        _bi("4. Watch Session Timeline", "4. Session Timeline ကြည့်ပါ"),
        _bi("Phases progress automatically as the AI works.",
            "AI လုပ်ဆောင်နေစဉ် phase များ အလိုအလျောက် တိုးတက်သည်။"),
        "#4caf50")
    h += _c(
        _bi("5. Review results", "5. ရလဒ်စစ်ဆေးပါ"),
        _bi("Check Vulnerabilities, AI Decisions, and Credentials tabs.",
            "Vulnerabilities, AI Decisions နှင့် Credentials tab များ စစ်ဆေးပါ။"),
        "#4caf50")
    h += _s(_bi("System Architecture", "စနစ်တည်ဆောက်ပုံ"))
    h += _pre(
        "Streamlit Frontend  (port 8501)  ←  Operator Dashboard\n"
        "         │\n"
        "         ▼\n"
        "FastAPI Backend  (port 6000)\n"
        "  Orchestrator │ Scanner │ AI Connector │ SQLite DB\n"
        "         │              │               │\n"
        "    AI Engine      Nmap/NSE        Shell Exec\n"
        "  (Ollama/API)   (Scanner)        (Kali env)"
    )
    h += _s(_bi("Attack Chain &#8212; Phase Order", "တိုက်ခိုက်မှုဆင့် &#8212; Phase အစဉ်"))
    h += _c(
        "<code>osint</code>",
        _bi("Passive intel: whois, dig, theHarvester, crt.sh, Google Dorks &#8212; domain targets only",
            "Passive intel: whois, dig, theHarvester, crt.sh, Google Dorks &#8212; domain ပစ်မှတ်များအတွက်သာ"),
        "#7e57c2")
    h += _c(
        "<code>reconnaissance</code>",
        _bi("Active scanning: Nmap top-1000 ports with service/version detection",
            "တက်ကြွသော scan: Nmap ဖြင့် port 1000 ကို service/version စစ်ဆေး"),
        "#1976d2")
    h += _c(
        "<code>enumeration</code>",
        _bi("Subdomain, endpoint, user, and share enumeration",
            "Subdomain, endpoint, user, share ရှာဖွေတင်ပြခြင်း"),
        "#0288d1")
    h += _c(
        "<code>vulnerability_analysis</code>",
        _bi("CVE mapping, nuclei, nikto, sqlmap",
            "CVE ပြည်ကြည့်, nuclei, nikto, sqlmap"),
        "#00838f")
    h += _c(
        "<code>exploitation</code>",
        _bi("Exploit execution via Metasploit or standalone tools",
            "Metasploit သို့မဟုတ် standalone tool ဖြင့် exploit လုပ်ဆောင်"),
        "#f57c00")
    h += _c(
        "<code>post_exploitation</code>",
        _bi("Shell stabilisation, local data collection",
            "Shell တည်မြဲစေပြီး local data ကောက်ခံ"),
        "#e64a19")
    h += _c(
        "<code>privilege_escalation</code>",
        _bi("linpeas, sudo -l, SUID checks, kernel exploits",
            "linpeas, sudo -l, SUID စစ်ဆေး, kernel exploit"),
        "#c62828")
    h += _c(
        "<code>lateral_movement</code>",
        _bi("Pivoting to adjacent hosts using found credentials",
            "ရှာဖွေတွေ့ credential ဖြင့် ကပ်လျက် host များသို့ ရွှေ့"),
        "#6a1b9a")
    h += _c(
        "<code>credential_reuse</code>",
        _bi("Credential spraying, pass-the-hash, Kerberoasting",
            "Credential ထပ်ကာသုံး, pass-the-hash, Kerberoasting"),
        "#2e7d32")
    h += _note(_bi(
        "Local IP targets (10.x, 192.168.x, 172.16&#8211;31.x): OSINT phase is automatically "
        "skipped &#8212; Google Dorks return nothing useful for private addresses.",
        "ဒေသဆိုင်ရာ IP ပစ်မှတ်များ (10.x, 192.168.x, 172.16&#8211;31.x): OSINT phase ကို "
        "အလိုအလျောက် ကျော်သည် &#8212; private address များအတွက် Google Dorks အသုံးမဝင်ပါ။"))
    return h


def _tab1() -> str:
    h = ""
    h += _s(_bi("Session Buttons", "Session ခလုတ်များ"))
    h += _c(
        "&#9654;&#65039; " + _bi("Resume", "Resume"),
        _bi("Continues AI analysis from current state &#8212; no re-scan. Safe on an already-running session (idempotent).",
            "AI စစ်ဆင်ရေးကို လက်ရှိ state မှ ဆက်လက်လုပ်ဆောင်သည် &#8212; rescan မလုပ်ဘဲ safe သည်"),
        "#4caf50")
    h += _c(
        "&#128260; " + _bi("Reset AI", "Reset AI"),
        _bi("Keeps nmap <b>scan data</b>. Clears AI decisions, commands, vulnerabilities. Re-runs AI from existing scan. Use when AI went off-track.",
            "nmap <b>scan data</b> ထားပြီး AI decisions, commands, vulnerabilities ဖျက်သည်။ AI လမ်းလွဲသွားသောအခါ သုံးပါ"),
        "#1976d2")
    h += _c(
        "&#128257; " + _bi("Full Rescan", "Full Rescan"),
        _bi("Clears everything &#8212; scan data + AI history. Runs nmap from scratch. Use when days have passed or target may have changed.",
            "အားလုံး ဖျက်ပြီး nmap ကို အစကနေ run သည်။ ရက်များကြာပြီ သို့မဟုတ် ပစ်မှတ် ပြောင်းနိုင်သောအခါ သုံးပါ"),
        "#f57c00")
    h += _c(
        "&#128465;&#65039; " + _bi("Delete", "Delete"),
        _bi("Permanently removes the session and all its data. Cannot be undone.",
            "Session နှင့် data အားလုံးကို ပြန်မရနိုင်ဘဲ ဖျက်သည်"),
        "#c62828")
    h += _s(_bi("Session Tabs", "Session tab များ"))
    h += _c(
        "&#128202; " + _bi("Overview", "Overview"),
        _bi("Session Timeline, controls, Strategic Layer AI planner with objective + progress %.",
            "Session Timeline, controls, Strategic Layer AI planner &#8212; objective နှင့် progress %"),
        "#4f8ef7")
    h += _c(
        "&#128269; " + _bi("Scan Results", "Scan Results"),
        _bi("All discovered hosts, open ports, running services with version info.",
            "ရှာဖွေတွေ့ host အားလုံး, ဖွင့်ထားသော port, service version"),
        "#4f8ef7")
    h += _c(
        "&#128737;&#65039; " + _bi("Vulnerabilities", "Vulnerabilities"),
        _bi("CVEs and weaknesses &#8212; from scanner, threat intel cache, and AI analysis.",
            "CVE များနှင့် အားနည်းချက်များ &#8212; scanner, threat intel cache, AI စစ်ဆေးချက်မှ"),
        "#4f8ef7")
    h += _c(
        "&#129302; " + _bi("AI Decisions", "AI Decisions"),
        _bi("Every AI reasoning step: what the AI was thinking, which command it chose and why.",
            "AI ၏ ဆုံးဖြတ်ချက်တိုင်း: AI ဘာတွေးနေသည်, ဘာကြောင့် ဘယ် command ရွေးသည်"),
        "#4f8ef7")
    h += _c(
        "&#9889; " + _bi("Commands", "Commands"),
        _bi("Full command history with output. Pending approval queue shown when manual review is needed.",
            "Command မှတ်တမ်းအပြည့်နှင့် output။ Manual review လိုအပ်သောအခါ approval queue ပြသည်"),
        "#4f8ef7")
    h += _c(
        "&#128193; " + _bi("Evidence", "Evidence"),
        _bi("Raw tool output saved as evidence: screenshots, file listings, service banners.",
            "သက်သေအဖြစ် သိမ်းဆည်းထားသော tool output: screenshots, file listings, service banners"),
        "#4f8ef7")
    h += _c(
        "&#128273; " + _bi("Credentials", "Credentials"),
        _bi("Extracted credentials &#8212; auto-parsed from john, hashcat, hydra output.",
            "ရှာဖွေတွေ့ credential များ &#8212; john, hashcat, hydra output မှ အလိုအလျောက် ဖတ်ယူ"),
        "#4f8ef7")
    h += _s(_bi("Timeline &#8212; Status Icons", "Timeline &#8212; Status အိုင်ကွန်များ"))
    h += _c("&#9989; " + _bi("Done", "Done"),
            _bi("Stage completed &#8212; AI decisions exist for this phase.",
                "Stage ပြီးဆုံးပြီ &#8212; ဤ phase အတွက် AI decisions ရှိပြီ"), "#455a64")
    h += _c("&#128260; " + _bi("Now", "Now"),
            _bi("Current active stage.", "လက်ရှိ လုပ်ဆောင်နေသော stage"), "#455a64")
    h += _c("&#9889; &#8212;",
            _bi("Stage was skipped (AI jumped past it).",
                "AI ကျော်သွားသော stage"), "#455a64")
    h += _c("&#9203; " + _bi("Next", "Next"),
            _bi("Not yet reached.", "မရောက်သေးသောနေ"), "#455a64")
    h += _s(_bi("Auto-Approve Explained", "Auto-Approve ရှင်းလင်းချက်"))
    h += _c(
        _bi("OFF (default)", "OFF (မူလ)"),
        _bi("All commands go to the pending queue for manual review before execution.",
            "Command အားလုံး manual review queue သို့ သွားသည်"),
        "#c62828")
    h += _c(
        "ON",
        _bi("All risk levels (LOW / MEDIUM / HIGH) execute automatically without waiting.",
            "Risk level အားလုံး (LOW / MEDIUM / HIGH) manual review မပါဘဲ အလိုအလျောက် run သည်"),
        "#4caf50")
    h += _note(_bi(
        "Two safeguards always apply:<br>"
        "(1) Allowlist gate &#8212; dangerous commands are always blocked.<br>"
        "(2) Depth checkpoint &#8212; after 15 auto-commands, one manual approval is required.",
        "ကာကွယ်ရေး ၂ ခု အမြဲတမ်း ရှိသည်:<br>"
        "(1) Allowlist gate &#8212; အန္တရာယ်ရှိ command များ အမြဲတမ်း ပိတ်ဆို့သည်<br>"
        "(2) Depth checkpoint &#8212; auto-command ၁၅ ခုပြီးသည့်နောက် manual approval တစ်ခု လိုအပ်သည်"))
    return h


def _tab2() -> str:
    h = ""
    h += _s(_bi("Risk Classification", "အန္တရာယ်အဆင့်သတ်မှတ်ချက်"))
    h += _c(
        "&#129001; " + _bi("LOW &#8212; Read-only / passive", "LOW &#8212; Read-only / passive"),
        _bi("No impact. Examples: <code>nmap</code>, <code>curl -I</code>, <code>whois</code>, <code>dig</code>. Auto-executes when auto-approve is ON.",
            "ဆိုးကျိုးမရှိ။ ဥပမာ: <code>nmap</code>, <code>curl -I</code>, <code>whois</code>, <code>dig</code>။ Auto-approve ON ဆိုရင် အလိုအလျောက် run သည်"),
        "#4caf50")
    h += _c(
        "&#128993; " + _bi("MEDIUM &#8212; Active / leaves traces", "MEDIUM &#8212; တက်ကြွသော / ခြေရာကျန်"),
        _bi("Enumeration &#8212; traces but no damage. Examples: <code>nikto</code>, <code>gobuster</code>, <code>nuclei</code>. Auto-executes when auto-approve is ON.",
            "ခြေရာကျန်သော်လည်း ပျက်စီးမှုမရှိ။ ဥပမာ: <code>nikto</code>, <code>gobuster</code>, <code>nuclei</code>"),
        "#f9a825")
    h += _c(
        "&#128308; " + _bi("HIGH &#8212; Destructive / irreversible", "HIGH &#8212; ဖျက်ဆီးနိုင် / ပြန်မပြင်နိုင်"),
        _bi("May crash services or exfiltrate data. Examples: <code>hydra</code>, <code>msfconsole</code>, <code>sqlmap --dump</code>. Requires manual approval.",
            "ဝန်ဆောင်မှုပျက်စီး သို့မဟုတ် data ယိုပေါက်နိုင်သည်။ Manual approval လိုအပ်သည်"),
        "#c62828")
    h += _note(_bi(
        "Risk level is determined by keyword + regex rules &#8212; not by the LLM. "
        "The AI cannot self-classify its command as LOW to bypass review.",
        "အန္တရာယ်အဆင့်ကို keyword + regex rules မှ သတ်မှတ်သည် &#8212; LLM မဟုတ်ပါ။ "
        "AI သည် review ကျော်လွှားရန် မိမိ command ကို LOW ဟု မသတ်မှတ်နိုင်ပါ"))
    h += _s(_bi("Strategic Layer (AI Planner)", "Strategic Layer (AI Planner)"))
    h += _c(
        _bi("Runs every 5 commands", "Command ၅ ခုတိုင်း run သည်"),
        _bi("Evaluates overall progress, updates the multi-step plan, writes a reflection, "
            "and declares objective complete when root/SYSTEM/Domain Admin is reached &#8212; halting the agentic loop.",
            "ကြုံကြိုက်တိုးတက်မှုကို စစ်ဆေး, multi-step plan ပြင်ဆင်, reflection ရေးသည်။ "
            "root/SYSTEM/Domain Admin ရသောအခါ objective ပြည့်ဆိုင်းကြေညာပြီး ရပ်သည်"),
        "#7e57c2")
    h += _c(
        _bi("Progress % frozen?", "Progress % ရပ်နေသည်?"),
        _bi("Progress updates only when the strategist runs (every 5 commands). Wait for the next batch of 5.",
            "Progress သည် strategist run သောအခါ (command ၅ ခုတိုင်း) မှသာ update ဖြစ်သည်"),
        "#455a64")
    h += _s(_bi("AI Decisions &#8212; Notable Findings", "AI Decisions &#8212; ထူးခြားသောတွေ့ရှိချက်"))
    h += _c(
        _bi("High-value keywords", "အရေးကြီးသော keyword များ"),
        _bi("Commands whose output contains: <code>password</code>, <code>hash</code>, <code>CVE</code>, "
            "<code>shell</code>, <code>admin</code>, <code>root</code>, <code>credential</code>, "
            "<code>exploit</code>, <code>vulnerable</code> &#8212; shown at the top of AI Decisions tab.",
            "Output ထဲတွင် <code>password</code>, <code>hash</code>, <code>CVE</code>, "
            "<code>shell</code>, <code>admin</code>, <code>root</code> စသည် ပါသော command များကို "
            "AI Decisions tab ထိပ်တွင် ပြသည်"),
        "#00838f")
    h += _s(_bi("Command Console", "Command Console"))
    h += _c(
        _bi("Manual command injection", "Manual command ထည့်ခြင်း"),
        _bi("Enter arbitrary commands against the session target &#8212; outside the AI loop. "
            "Useful for running a specific tool the AI has not tried, or verifying a finding.",
            "Session ပစ်မှတ်ကို AI loop အပြင်မှ command ထည့်လုပ်ဆောင်နိုင်သည်။ "
            "AI မစမ်းသေးသော tool တစ်ခု run ရန် သို့မဟုတ် တွေ့ရှိချက် အတည်ပြုရန် အသုံးဝင်သည်"),
        "#1976d2")
    h += _s("OSINT &#8212; Google Dorks")
    h += _pre(
        "site:<domain> filetype:pdf|xlsx|docx|pptx|sql|bak|env|config|log\n"
        "site:<domain> inurl:admin|login|portal|dashboard\n"
        'site:<domain> "index of" | "parent directory"\n'
        '"<domain>" ext:sql|bak|env|config|log\n'
        'site:<domain> intext:"password"|"api_key"|"secret"'
    )
    h += _note(_bi(
        "OSINT / Google Dorks only run for domain targets. "
        "Private/local IPs (10.x, 192.168.x) skip OSINT automatically.",
        "OSINT / Google Dorks သည် domain ပစ်မှတ်များအတွက်သာ run သည်။ "
        "ဒေသဆိုင်ရာ IP (10.x, 192.168.x) တွေကို OSINT ကျော်သည်"))
    return h


def _tab3() -> str:
    h = ""
    h += _s(_bi("What is Threat Intel?", "Threat Intel ဆိုတာဘာလဲ?"))
    h += _c(
        _bi("Standalone research tool", "သီးသန့် သုတေသနကိရိယာ"),
        _bi("The Threat Intel page builds a local vulnerability knowledge base over time. "
            "Completely separate from live pentest sessions &#8212; never issues shell commands.",
            "Threat Intel page သည် local vulnerability knowledge base ကို တဖြည်းဖြည်း တည်ဆောက်သည်။ "
            "Live pentest session နှင့် လုံးဝ သီးသန့်ဖြစ်ပြီး shell command ဘယ်တော့မှ မထည့်"),
        "#7e57c2")
    h += _s(_bi("How It Works", "လုပ်ဆောင်ပုံ"))
    h += _c(
        _bi("1. Enter a search topic", "1. ရှာဖွေမည့် topic ထည့်ပါ"),
        _bi("Software name, version, or CVE query &#8212; e.g. <code>Apache httpd 2.4.49</code>, <code>GlassFish 4.1</code>.",
            "Software အမည်, version သို့မဟုတ် CVE query &#8212; ဥပမာ <code>Apache httpd 2.4.49</code>"),
        "#1976d2")
    h += _c(
        _bi("2. DuckDuckGo search", "2. DuckDuckGo ဖြင့် ရှာဖွေ"),
        _bi("Searches for <code>[topic] CVE vulnerability</code> and fetches up to 5 result pages.",
            "<code>[topic] CVE vulnerability</code> ကို ရှာပြီး ရလဒ် page ၅ ခုထိ ဖတ်သည်"),
        "#1976d2")
    h += _c(
        _bi("3. AI extraction", "3. AI ဖြင့် ထုတ်ယူ"),
        _bi("Each page&#39;s text is sent to the AI using an isolated prompt &#8212; separate from the pentest AI.",
            "Page တစ်ခုချင်းစီ၏ text ကို သီးသန့် prompt ဖြင့် AI သို့ ပို့သည် &#8212; pentest AI နှင့် သီးသန့်"),
        "#1976d2")
    h += _c(
        _bi("4. Structured storage", "4. ဖွဲ့စည်းတည်ဆောက်ထားသော သိမ်းဆည်းမှု"),
        _bi("CVE IDs, title, description, severity stored in SQLite <code>threat_intel_cache</code> with <code>verified=False</code>.",
            "CVE IDs, title, description, severity တို့ကို SQLite <code>threat_intel_cache</code> ထဲ သိမ်းသည်"),
        "#1976d2")
    h += _c(
        _bi("5. Auto cross-reference", "5. အလိုအလျောက် ညှိနှိုင်းစိစစ်"),
        _bi("After every nmap scan, orchestrator cross-references service names against the cache. "
            "Matches are added to the Vulnerabilities tab.",
            "nmap scan တိုင်းပြီးသည့်နောက် orchestrator သည် service name များကို cache နှင့် ညှိနှိုင်းသည်"),
        "#1976d2")
    h += _note(_bi(
        "All findings are unverified by design. Web pages can be wrong or outdated. "
        "Cross-check CVE IDs against NVD, Vulners, or CISA KEV before acting.",
        "တွေ့ရှိချက်အားလုံး မစစ်ဆေးသေးသော ရလဒ်ဖြစ်သည်။ Web page များ မှားနိုင် သို့မဟုတ် ရက်ကြာနိုင်သည်။ "
        "လုပ်ဆောင်မတိုင်ခင် NVD, Vulners, CISA KEV နှင့် ညှိနှိုင်းစစ်ဆေးပါ"), "aw")
    h += _s(_bi("Useful Search Topics", "အသုံးဝင်သော ရှာဖွေမှု topic များ"))
    h += _c("<code>Apache httpd 2.4.49</code>",
            _bi("Example finding: CVE-2021-41773 path traversal RCE",
                "တွေ့ရှိချက် ဥပမာ: CVE-2021-41773 path traversal RCE"), "#00838f")
    h += _c("<code>ProFTPD 1.3.5</code>",
            _bi("Example finding: mod_copy unauthenticated RCE",
                "တွေ့ရှိချက် ဥပမာ: mod_copy unauthenticated RCE"), "#00838f")
    h += _c("<code>OpenSSH 7.2p2</code>",
            _bi("Example finding: Username enumeration CVE",
                "တွေ့ရှိချက် ဥပမာ: Username enumeration CVE"), "#00838f")
    h += _c("<code>GlassFish 4.1</code>",
            _bi("Example finding: CVE-2017-1000028 unauthenticated RCE",
                "တွေ့ရှိချက် ဥပမာ: CVE-2017-1000028 unauthenticated RCE"), "#00838f")
    h += _c("<code>Tomcat 7.0</code>",
            _bi("Example finding: CVE-2020-1938 Ghostcat AJP RCE",
                "တွေ့ရှိချက် ဥပမာ: CVE-2020-1938 Ghostcat AJP RCE"), "#00838f")
    return h


def _tab4() -> str:
    h = ""
    h += _s(_bi("What the AI Needs to Do Well", "AI ကောင်းကောင်းလုပ်ဆောင်နိုင်ဖို့ လိုအပ်ချက်များ"))
    h += _c(
        _bi("1. Structured JSON output", "1. ဖွဲ့စည်းပုံကျသော JSON output"),
        _bi("Every AI response must be valid JSON. A model that garbles this causes parse failures and halts the session.",
            "AI response တိုင်း valid JSON ဖြစ်ရမည်။ ဤအချက် မကျသော model သည် parse failure ဖြစ်ပြီး session ရပ်နိုင်သည်"),
        "#1976d2")
    h += _c(
        _bi("2. Multi-step reasoning", "2. တဆင့်ပြီးတဆင့် တွေးတောဆင်ခြင်"),
        _bi("The model must plan a full attack chain without skipping phases after just 3 commands.",
            "Model သည် command ၃ ခုနှင့် phase ကျော်မသွားဘဲ attack chain အပြည့် စီစဉ်နိုင်ရမည်"),
        "#1976d2")
    h += _c(
        _bi("3. Security command vocabulary", "3. လုံခြုံရေးဆိုင်ရာ command ဗဟုသုတ"),
        _bi("Knows nmap flags, CVE identifiers, Metasploit modules, GlassFish/Tomcat/SMB quirks.",
            "nmap flags, CVE identifier, Metasploit module, GlassFish/Tomcat/SMB အထူးသဘောကို နားလည်သည်"),
        "#1976d2")
    h += _s(_bi("DeepHat vs qwen2.5 &#8212; Which to Use?", "DeepHat vs qwen2.5 &#8212; ဘယ်ဟာ သုံးမလဲ?"))
    h += _c(
        "DeepHat V1-7B",
        _bi("<b>Base:</b> Qwen2.5-Coder-7B cybersecurity fine-tune | <b>7.61B parameters</b><br>"
            "OK Security vocab &#8212; CVE IDs natively understood<br>"
            "Weaker reasoning &#8594; stage-skipping | JSON inconsistent &#8594; parse errors | NOT fully uncensored",
            "<b>Base:</b> Qwen2.5-Coder-7B cybersecurity fine-tune | <b>7.61B parameters</b><br>"
            "Security vocab OK &#8212; CVE ID နားလည်<br>"
            "Reasoning အားနည်း &#8594; stage ကျော် | JSON မသေချာ &#8594; parse error | Fully uncensored မဟုတ်"),
        "#f57c00")
    h += _c(
        _bi("qwen2.5:14b &#8212; Recommended", "qwen2.5:14b &#8212; အကြံပြုသည်"),
        _bi("<b>Base:</b> Qwen2.5 14B (Alibaba) | <b>14.7B parameters</b><br>"
            "2&#215; parameters &#8594; better JSON reliability | Better multi-step reasoning | Fewer stage-skip bugs<br>"
            "Not cybersecurity-specialized | Requires ~11 GB RAM",
            "<b>Base:</b> Qwen2.5 14B (Alibaba) | <b>14.7B parameters</b><br>"
            "Parameter ၂ ဆ &#8594; JSON ပိုယုံကြည်ရ | Multi-step reasoning ပိုကောင်း<br>"
            "Cybersecurity အထူး မဟုတ် | RAM ~11 GB လိုအပ်"),
        "#4caf50")
    h += _note(_bi(
        "Use <code>qwen2.5:14b</code> as primary. The #1 cause of session failures is bad JSON output "
        "and premature stage advancement &#8212; both are reasoning problems a larger model solves.",
        "<code>qwen2.5:14b</code> ကို အဓိက သုံးပါ။ Session failure ၏ အဓိကအကြောင်းရင်း #1 မှာ "
        "မမှန်ကန်သော JSON output နှင့် phase အချိန်မတန်ကူးခြင်း &#8212; ၂ ခုလုံး model ကြီးလာသောအခါ ပိုကောင်းသည်"), "ao")
    h += _s(_bi("Hardware Recommendations", "Hardware အကြံပြုချက်"))
    h += _c(
        _bi("M2 Mac Mini &#8212; 24 GB RAM (current)", "M2 Mac Mini &#8212; 24 GB RAM (လက်ရှိ)"),
        _bi("Primary: <code>qwen2.5:14b</code> &#8212; ~9 GB disk, ~11 GB RAM, context 32,768<br>"
            "Alt: <code>deepseek-r1:14b</code><br>"
            "Stretch: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, ~21 GB RAM",
            "အဓိက: <code>qwen2.5:14b</code> &#8212; ~9 GB disk, ~11 GB RAM, context 32,768<br>"
            "အစားထိုး: <code>deepseek-r1:14b</code><br>"
            "စွန့်စားပါက: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, ~21 GB RAM"),
        "#1976d2")
    h += _c(
        _bi("M4 Pro &#8212; 64 GB RAM (upcoming)", "M4 Pro &#8212; 64 GB RAM (လာမည်)"),
        _bi("Primary: <code>qwen2.5:72b</code> &#8212; ~42 GB disk, ~45 GB RAM, context 131,072<br>"
            "Alt: <code>deepseek-r1:70b</code><br>"
            "Lighter: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, context 65,536",
            "အဓိက: <code>qwen2.5:72b</code> &#8212; ~42 GB disk, ~45 GB RAM, context 131,072<br>"
            "အစားထိုး: <code>deepseek-r1:70b</code><br>"
            "ပေါ့ပါးသော: <code>qwen2.5:32b</code> &#8212; ~19 GB disk, context 65,536"),
        "#7e57c2")
    h += _s(_bi("Quick Setup", "အမြန်သတ်မှတ်ခြင်း"))
    h += (
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:10px 0">'
        '<div><div class="card" style="border-left-color:#1976d2">'
        '<div class="ct">M2 Mac Mini 24GB</div>'
        '<div class="cb">Model <code>qwen2.5:14b</code>, Context <code>32768</code></div>'
        '</div><pre><code>ollama pull qwen2.5:14b</code></pre></div>'
        '<div><div class="card" style="border-left-color:#7e57c2">'
        '<div class="ct">M4 Pro 64GB</div>'
        '<div class="cb">Model <code>qwen2.5:72b</code>, Context <code>65536</code></div>'
        '</div><pre><code>ollama pull qwen2.5:72b</code></pre></div></div>'
    )
    h += _s(_bi("Context Window &#8212; Why It Matters", "Context Window &#8212; ဘာကြောင့် အရေးကြီးသလဲ"))
    h += _c(
        _bi("What happens when context overflows", "Context လျှံသွားသောအခါ"),
        _bi("Local models have a fixed context window. When session history exceeds it, the model silently "
            "forgets old content &#8212; causing repeated commands, stage regression, or hallucinated progress.",
            "Local model တွင် fixed context window ရှိသည်။ Session history ကျော်သွားသောအခါ "
            "model သည် ဟောင်းသော content ကို တိတ်တဆိတ် မေ့ပြီး command ထပ်, phase ပြန်ဆုတ် သို့မဟုတ် progress ဟန်ဆောင်နိုင်သည်"),
        "#f57c00")
    h += _c(
        _bi("Built-in mitigations", "Built-in ဖြေရှင်းနည်းများ"),
        _bi("1. Episode summaries &#8212; every N commands, old history is compressed and re-injected.<br>"
            "2. Configurable context window &#8212; Settings &#8594; AI Configuration &#8594; "
            "Context window controls Ollama&#39;s <code>num_ctx</code>.",
            "1. Episode summaries &#8212; command N ခုတိုင်း ဟောင်းသော history ကို ချုံ့ပြီး ပြန်ထည့်သည်<br>"
            "2. Context window သတ်မှတ်နိုင် &#8212; Settings &#8594; AI Configuration &#8594; "
            "Context window ဖြင့် Ollama ၏ <code>num_ctx</code> ထိန်းချုပ်"),
        "#4caf50")
    h += (
        '<table class="tbl"><tr><th>' +
        _bi("Model size", "Model အရွယ်") +
        '</th><th>' +
        _bi("Safe context window", "ဘေးကင်းသော context window") +
        '</th></tr>'
        "<tr><td>7&#8211;8B</td><td>16,384</td></tr>"
        "<tr><td>13&#8211;14B</td><td>32,768</td></tr>"
        "<tr><td>32B</td><td>32,768&#8211;65,536</td></tr>"
        "<tr><td>70&#8211;72B</td><td>65,536&#8211;131,072</td></tr></table>"
    )
    return h


def _tab5() -> str:
    h = ""
    h += _s(_bi("Common Issues", "ဖြစ်လေ့ဖြစ်ထ ပြဿနာများ"))
    h += _exp(
        _bi("Session status FAILED but terminal still active",
            "Session FAILED ဖြစ်သော်လည်း terminal တက်ကြွနေဆဲ"),
        _bi("Asyncio tasks queued before failure finish running after status changed. Normal &#8212; "
            "backend drains queue then stops. Wait a few seconds, refresh, then use Reset AI.",
            "Failure မတိုင်ခင် queue ထဲ ရှိသော asyncio task များ status ပြောင်းပြီးနောက် ဆက် run သည်။ "
            "ပုံမှန်ဖြစ်ရပ် &#8212; backend queue ကုန်ပြီးနောက် ရပ်မည်။ စက္ကန့်အနည်းငယ် စောင့်ပြီး refresh လုပ်ကာ Reset AI သုံးပါ"))
    h += _exp(
        _bi("&#39;AI response parsing error&#39; in command history",
            "Command history ထဲ &#39;AI response parsing error&#39; ပြနေ"),
        _bi("AI returned invalid JSON. Session now halts cleanly on parse failure. "
            "If seen on an old session, do a Reset AI. Switching to qwen2.5:14b reduces parse failures.",
            "AI ၏ JSON မမှန်ကန်ခဲ့သည်။ Session သည် parse failure တွင် ယခု သပ်ရပ်စွာ ရပ်နိုင်သည်။ "
            "ဟောင်းသော session တွင် တွေ့ပါက Reset AI လုပ်ပါ၊ qwen2.5:14b သို့ ပြောင်းပါ"))
    h += _exp(
        _bi("All stages Done after only 5 commands",
            "Command ၅ ခုနှင့် stage အားလုံး Done ဖြစ်"),
        _bi("Old bug: AI jumped to credential_reuse immediately. Fixed &#8212; stage gate prevents "
            "advancing more than 1 phase per AI decision. Do a Reset AI.",
            "ဟောင်းသောပျက်ချို: AI ချက်ချင်း credential_reuse သို့ ခုန်ခဲ့သည်။ ပြင်ဆင်ပြီး &#8212; "
            "stage gate သည် AI decision တစ်ခုတွင် phase ၁ ခုထက် မကူးရန် တားဆီးသည်"))
    h += _exp(
        _bi("Progress % frozen at 5%", "Progress % ၅% မှာ ရပ်နေ"),
        _bi("Strategic Layer runs every 5 completed commands. Wait for next batch of 5, or do a Reset AI.",
            "Strategic Layer သည် command ၅ ခုပြည့်တိုင်း run သည်။ နောက်ထပ် ၅ ခုကို စောင့်ပါ သို့မဟုတ် Reset AI လုပ်ပါ"))
    h += _exp(
        _bi("Resume button showing on active session", "တက်ကြွနေသော session တွင် Resume ပြ"),
        _bi("Fixed &#8212; &#39;ready&#39; now shows Session Active instead. Update and restart the frontend.",
            "ပြင်ဆင်ပြီး &#8212; &#39;ready&#39; သည် ယခု Session Active ပြသည်။ Update ပြီး frontend restart လုပ်ပါ"))
    h += _exp(
        _bi("Pending commands piling up", "ဆိုင်းငံ့ command များ ထပ်နေ"),
        _bi("Two causes: (1) auto_approve OFF &#8212; commands go to queue by design. "
            "(2) Max auto-depth reached (15 commands) &#8212; one manual approval resets the counter.",
            "အကြောင်းရင်း ၂ ခု: (1) auto_approve OFF &#8212; command များ queue သို့ သွားသည် "
            "(2) Max auto-depth (command ၁၅ ခု) ပြည့် &#8212; manual approval တစ်ခု counter reset လုပ်သည်"))
    h += _exp(
        _bi("AI keeps suggesting the same command repeatedly",
            "AI တူညီသော command ကိုပဲ ဆပ်ပြာတင်နေ"),
        _bi("Context overflow &#8212; model forgot it ran that command. Increase context window in "
            "Settings (try 32768 or 65536). Switch to a larger model (14B+).",
            "Context လွန်ကဲမှု &#8212; model သည် ထို command run ခဲ့ကြောင်း မေ့သွားသည်။ "
            "Settings တွင် context window တိုးပါ (32768 သို့မဟုတ် 65536 ကြိုးစားပါ)"))
    h += _exp(
        _bi("Session History shows &#39;No sessions recorded yet&#39;",
            "Session History &#39;No sessions recorded yet&#39; ပြ"),
        _bi("Fixed &#8212; caused by FastAPI route order bug. Update to latest and restart backend.",
            "ပြင်ဆင်ပြီး &#8212; FastAPI route order ပျက်ချိုမှုကြောင့် ဖြစ်ခဲ့သည်"))
    h += _exp(
        _bi("OSINT running on local/private IP targets",
            "ဒေသဆိုင်ရာ IP တွင် OSINT run နေ"),
        _bi("Fixed &#8212; private IPs (10.x, 192.168.x, 172.16&#8211;31.x, localhost) now skip OSINT automatically.",
            "ပြင်ဆင်ပြီး &#8212; private IP (10.x, 192.168.x, 172.16&#8211;31.x, localhost) တွေကို OSINT ကျော်သည်"))
    h += _exp(
        _bi("Backend not starting / port conflict", "Backend မစ / port ပဋိပက္ခ"),
        _bi("start.sh auto-detects port conflicts and finds the next free port. "
            "Set BACKEND_PORT / FRONTEND_PORT in .env to override.",
            "start.sh သည် port ပဋိပက္ခကို အလိုအလျောက် ရှာပြီး နောက်ထပ် free port ရှာသည်။ "
            ".env ထဲ BACKEND_PORT / FRONTEND_PORT သတ်မှတ်ပါ"))
    h += _s(_bi("Port Configuration", "Port သတ်မှတ်ချက်"))
    h += _pre("# .env\nBACKEND_PORT=6000    # FastAPI backend\nFRONTEND_PORT=8501   # Streamlit frontend\nDOCS_PORT=3500       # Documentation server")
    h += _s(_bi("API Reference &#8212; Key Endpoints", "API အကိုးအကား &#8212; အဓိက Endpoint များ"))
    h += (
        '<table class="tbl">'
        "<tr><th>Method</th><th>Endpoint</th><th>" + _bi("Description", "ဖော်ပြချက်") + "</th></tr>"
        "<tr><td>POST</td><td>/api/sessions</td><td>" + _bi("Create new session", "Session အသစ် ဖန်တီး") + "</td></tr>"
        "<tr><td>GET</td><td>/api/sessions/history</td><td>" + _bi("List all sessions", "Session အားလုံး စာရင်း") + "</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/resume</td><td>" + _bi("Resume AI (idempotent)", "AI ဆက်လုပ် (idempotent)") + "</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/restart</td><td>" + _bi("Reset AI, keep scan data", "AI reset, scan data ထား") + "</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/rescan</td><td>" + _bi("Full rescan &#8212; clear all, re-run nmap", "Full rescan &#8212; အားလုံးဖျက်, nmap ပြန်") + "</td></tr>"
        "<tr><td>POST</td><td>/api/sessions/{id}/approve/{cmd_id}</td><td>" + _bi("Approve pending command", "ဆိုင်းငံ့ command အတည်ပြု") + "</td></tr>"
        "<tr><td>DELETE</td><td>/api/sessions/{id}</td><td>" + _bi("Delete session", "Session ဖျက်") + "</td></tr>"
        "<tr><td>GET</td><td>/api/stats</td><td>" + _bi("Dashboard stats", "Dashboard စာရင်းဇယား") + "</td></tr>"
        "</table>"
    )
    return h


# ---------------------------------------------------------------------------
# Full HTML assembly
# ---------------------------------------------------------------------------

_CSS = (
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#0e1117;color:#e8eaf6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    "padding:24px 32px;font-size:14px;line-height:1.5;max-width:1100px;margin:0 auto}"
    "h1{color:#e8eaf6;font-size:1.6rem}"
    ".hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}"
    ".lang-toggle{background:#1e2530;color:#90caf9;border:1px solid #2a3040;"
    "padding:6px 18px;border-radius:6px;cursor:pointer;font-size:.9rem;font-weight:700;"
    "transition:all .15s;white-space:nowrap}"
    ".lang-toggle:hover{background:#2a3040;color:#e8eaf6}"
    ".tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}"
    ".tb{background:#1e2530;color:#90caf9;border:1px solid #2a3040;padding:8px 14px;"
    "border-radius:6px;cursor:pointer;font-size:.85rem;transition:all .15s}"
    ".tb.ta{background:#4f8ef7;color:#fff;border-color:#4f8ef7}"
    ".card{background:#1e2530;border-left:4px solid #4f8ef7;padding:14px 18px;border-radius:6px;margin:8px 0}"
    ".ct{color:#e8eaf6;font-weight:600;font-size:1rem;margin-bottom:5px}"
    ".cb{color:#b0bec5;line-height:1.7}"
    ".sh{color:#90caf9;font-size:1.1rem;font-weight:700;margin:22px 0 8px;padding-bottom:4px;border-bottom:1px solid #2a3040}"
    ".alert{padding:12px 16px;border-radius:6px;margin:10px 0;line-height:1.6}"
    ".ai{background:#1a2744;border:1px solid #2196f3;color:#90caf9}"
    ".aw{background:#2d1f00;border:1px solid #f57c00;color:#ffb74d}"
    ".ao{background:#1a2d1a;border:1px solid #4caf50;color:#81c784}"
    "code{background:#2a3040;padding:2px 5px;border-radius:3px;font-family:monospace;font-size:.88em}"
    "pre{background:#1e2530;border:1px solid #2a3040;padding:12px;border-radius:6px;"
    "overflow-x:auto;margin:10px 0;font-size:.83rem;color:#b0bec5;white-space:pre}"
    "details.exp{border:1px solid #2a3040;border-radius:6px;margin:6px 0;overflow:hidden}"
    "details.exp summary{background:#1e2530;padding:12px 16px;cursor:pointer;color:#90caf9;"
    "list-style:none;user-select:none}"
    "details.exp summary::-webkit-details-marker{display:none}"
    "details.exp summary::after{content:' ▼';font-size:.75rem;float:right;opacity:.7}"
    "details[open].exp summary::after{content:' ▲'}"
    ".exb{padding:14px 16px;background:#141920;color:#b0bec5;line-height:1.7}"
    ".tbl{width:100%;border-collapse:collapse;margin:12px 0;font-size:.85rem}"
    ".tbl th{background:#1e2530;color:#90caf9;padding:9px 12px;text-align:left;border:1px solid #2a3040}"
    ".tbl td{padding:8px 12px;border:1px solid #2a3040;color:#b0bec5}"
    ".tbl tr:nth-child(even) td{background:#141920}"
    ".my{display:none}"
    "body.lang-my .en{display:none}"
    "body.lang-my .my{display:inline}"
    "</style>"
)

_JS = (
    "<script>"
    "function sT(n){"
    "var ps=document.querySelectorAll('.tp');"
    "var bs=document.querySelectorAll('.tb');"
    "for(var i=0;i<ps.length;i++){ps[i].style.display=i===n?'block':'none';}"
    "for(var i=0;i<bs.length;i++){bs[i].className=i===n?'tb ta':'tb';}"
    "}"
    "function toggleLang(){"
    "var toMy=!document.body.classList.contains('lang-my');"
    "document.body.classList.toggle('lang-my',toMy);"
    "localStorage.setItem('lang',toMy?'my':'en');"
    "}"
    "(function(){"
    "if(localStorage.getItem('lang')==='my')document.body.classList.add('lang-my');"
    "})();"
    "</script>"
)

_TABS_CONTENT = [_tab0, _tab1, _tab2, _tab3, _tab4, _tab5]
_TAB_LABELS_EN = [
    "&#128640; Getting Started",
    "&#128203; Session Guide",
    "&#129302; AI &amp; Commands",
    "&#128376;&#65039; Threat Intel",
    "&#129504; Ollama Models",
    "&#128295; Troubleshooting",
]
_TAB_LABELS_MY = [
    "&#128640; စတင်နည်း",
    "&#128203; Session လမ်းညွှန်",
    "&#129302; AI &amp; Commands",
    "&#128376;&#65039; Threat Intel",
    "&#129504; Ollama မော်ဒယ်",
    "&#128295; ပြဿနာဖြေရှင်းနည်း",
]


def _build_html() -> str:
    buttons = "".join(
        f'<button class="tb{" ta" if i == 0 else ""}" onclick="sT({i})">'
        f'{_bi(en, my)}</button>'
        for i, (en, my) in enumerate(zip(_TAB_LABELS_EN, _TAB_LABELS_MY))
    )
    panels = "".join(
        f'<div class="tp" style="display:{"block" if i == 0 else "none"}">{fn()}</div>'
        for i, fn in enumerate(_TABS_CONTENT)
    )
    header = (
        '<div class="hdr">'
        "<h1>&#128218; KMN-CyberSeek Documentation</h1>"
        '<button class="lang-toggle" onclick="toggleLang()">'
        '<span class="en">မြန်မာ</span><span class="my">English</span>'
        "</button>"
        "</div>"
    )
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>KMN-CyberSeek Documentation</title>"
        + _CSS
        + "</head><body>"
        + header
        + '<div class="tabs">' + buttons + "</div>"
        + panels
        + _JS
        + "</body></html>"
    )


# Build once at import time.
_PAGE = _build_html()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = _PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        pass


class _ReuseServer(socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    with _ReuseServer(("", DOCS_PORT), _Handler) as httpd:
        print(f"Docs server listening on http://0.0.0.0:{DOCS_PORT}")
        httpd.serve_forever()
