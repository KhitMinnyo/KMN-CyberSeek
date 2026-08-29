"""Tests for the playbook registry (core/playbooks.py) — the Coverage Engine M1
foundation. Verifies service classification, step schema integrity, and
deterministic command rendering. Pure data — no external tools needed."""

from core import playbooks as pb


def test_every_playbook_step_is_wellformed():
    seen = set()
    for key, steps in pb.PLAYBOOKS.items():
        assert steps, f"empty playbook: {key}"
        for st in steps:
            assert st.id and st.id not in seen, f"missing/duplicate step id: {st.id}"
            seen.add(st.id)
            assert st.kind in (pb.KIND_DET, pb.KIND_AI)
            assert st.phase in (pb.PHASE_ENUM, pb.PHASE_VULN, pb.PHASE_EXPLOIT, pb.PHASE_POST)
            if st.kind == pb.KIND_DET:
                assert st.command, f"deterministic step without command: {st.id}"


def test_classify_web_and_tech_specific():
    tomcat = {"service": "http", "port": 8080, "version": "Apache Tomcat 8.5"}
    keys = pb.classify_service(tomcat)
    assert "http" in keys and "tomcat" in keys

    glassfish = {"service": "ssl/http", "port": 4848, "version": "Sun GlassFish 4.1.1"}
    assert "glassfish" in pb.classify_service(glassfish)

    jenkins = {"service": "http", "port": 8888, "version": "Jetty 9.4.45"}
    assert "jenkins" in pb.classify_service(jenkins)


def test_classify_network_and_db_services():
    assert "smb" in pb.classify_service({"service": "microsoft-ds", "port": 445})
    assert "smb" in pb.classify_service({"service": "netbios-ssn", "port": 139})
    assert "ftp" in pb.classify_service({"service": "ftp", "port": 21})
    assert "ssh" in pb.classify_service({"service": "ssh", "port": 22})
    assert "mysql" in pb.classify_service({"service": "mysql", "port": 3306, "version": "MariaDB 5.5"})
    assert "rdp" in pb.classify_service({"service": "ms-wbt-server", "port": 3389})
    assert "winrm" in pb.classify_service({"service": "http", "port": 5985})
    assert "tomcat" in pb.classify_service({"service": "ajp13", "port": 8009})
    assert "postgresql" in pb.classify_service({"service": "postgresql", "port": 5432})
    assert "redis" in pb.classify_service({"service": "unknown", "port": 6379})
    assert "rmi" in pb.classify_service({"service": "java-rmi", "port": 1099})
    assert "nfs" in pb.classify_service({"service": "nfs", "port": 2049})
    assert "vnc" in pb.classify_service({"service": "vnc", "port": 5900})
    assert "ipp" in pb.classify_service({"service": "ipp", "port": 631})


def test_classify_falls_back_to_generic():
    assert pb.classify_service({"service": "unknown-weird", "port": 65000}) == ["generic"]


def test_deterministic_step_renders_command():
    steps = pb.get_steps(["smb"])
    enum = next(s for s in steps if s.id == "smb.enum4linux")
    cmd = enum.render({"host": "10.0.0.5"})
    assert cmd == "enum4linux-ng -A 10.0.0.5"


def test_http_url_rendering_with_tls_and_port():
    steps = pb.get_steps(["http"])
    whatweb = next(s for s in steps if s.id == "http.whatweb")
    cmd = whatweb.render({"host": "10.0.0.5", "port": 443, "tls": True})
    assert cmd == "whatweb -a 3 https://10.0.0.5:443"


def test_ai_step_renders_none():
    steps = pb.get_steps(["mysql"])
    fw = next(s for s in steps if s.id == "mysql.file_write")
    assert fw.kind == pb.KIND_AI
    assert fw.render({"host": "10.0.0.5"}) is None


def test_applies_if_gates_wordpress_and_webdav():
    steps = pb.get_steps(["http"])
    wpscan = next(s for s in steps if s.id == "http.wpscan")
    assert wpscan.applies_if({"tech": ["WordPress 5.0"]}) is True
    assert wpscan.applies_if({"tech": ["Apache"]}) is False
    webdav = next(s for s in steps if s.id == "http.webdav")
    assert webdav.applies_if({"tech": ["WebDAV"]}) is True


def test_get_steps_dedups_across_keys():
    steps = pb.get_steps(["http", "http", "tomcat"])
    ids = [s.id for s in steps]
    assert len(ids) == len(set(ids))
