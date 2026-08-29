"""Tests for command-level scope enforcement and tool validators — no live target."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.validators import (
    extract_command_destinations, check_command_scope,
    tool_validate, validate_msf_session_open, validate_ssh_auth,
    validate_winrm_auth, validate_smb_auth, validate_web_rce,
    validate_root_privilege, validate_credential, validate_ftp_access,
)


def test_extract_rhosts():
    dests = extract_command_destinations("set RHOSTS 10.0.0.5")
    assert "10.0.0.5" in dests

def test_extract_url_host():
    dests = extract_command_destinations("curl http://192.168.1.100/login")
    assert "192.168.1.100" in dests

def test_extract_smb_dest():
    dests = extract_command_destinations("smbclient //10.10.10.5/share")
    assert "10.10.10.5" in dests

def test_extract_cidr_arg():
    dests = extract_command_destinations("nmap -sV 192.168.1.0/24")
    assert "192.168.1.0/24" in dests

def test_no_destinations_empty():
    assert extract_command_destinations("") == []

def test_scope_check_pass():
    assert check_command_scope("set RHOSTS 10.0.0.5", "10.0.0.0/24") is None

def test_scope_check_fail():
    reason = check_command_scope("curl http://8.8.8.8/", "10.0.0.0/24")
    assert reason is not None
    assert "8.8.8.8" in reason

def test_scope_check_no_allowlist():
    assert check_command_scope("set RHOSTS 1.2.3.4", "") is None

def test_msf_session_open_positive():
    assert validate_msf_session_open("Meterpreter session 1 opened (10.0.0.1:4444)")

def test_msf_session_open_negative():
    assert not validate_msf_session_open("Exploit completed but no session created")

def test_ssh_auth_positive():
    assert validate_ssh_auth("Welcome to Ubuntu 20.04\n$ ")

def test_ssh_auth_negative():
    assert not validate_ssh_auth("Permission denied (publickey,password).")

def test_winrm_positive():
    assert validate_winrm_auth(r"Evil-WinRM shell v3.5" + "\n" + r"PS C:\Users\Administrator>")

def test_winrm_negative():
    assert not validate_winrm_auth("WinRM::WinRMAuthorizationError")

def test_smb_positive():
    assert validate_smb_auth("Sharename       Type      Comment")

def test_smb_negative():
    assert not validate_smb_auth("NT_STATUS_LOGON_FAILURE")

def test_web_rce_nonce():
    assert validate_web_rce("... KMN_RCE_DEADBEEF ...", nonce="KMN_RCE_DEADBEEF")
    assert not validate_web_rce("no nonce here", nonce="KMN_RCE_DEADBEEF")

def test_root_priv_linux():
    assert validate_root_privilege("uid=0(root) gid=0(root) groups=0(root)")

def test_root_priv_windows():
    assert validate_root_privilege(r"NT AUTHORITY\SYSTEM")

def test_root_priv_negative():
    assert not validate_root_privilege("uid=1000(user) gid=1000(user)")

def test_credential_positive():
    assert validate_credential("[+] Valid credentials found")

def test_ftp_positive():
    assert validate_ftp_access("230 Login successful.")

def test_ftp_negative():
    assert not validate_ftp_access("530 Login incorrect.")

def test_tool_validate_dispatch():
    assert tool_validate("msf_session", "Meterpreter session 2 opened")
    assert not tool_validate("ssh", "Permission denied")
    assert not tool_validate("nonexistent_tool", "anything")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
    print("All tests passed.")
