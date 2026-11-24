import pytest
from argos.backend.attack.pentest.nmap_parser import NmapParseError, parse_nmap_xml


def scan(target: str = "127.0.0.1") -> bytes:
    return (
        f'<nmaprun><host><address addr="{target}" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" version="9.2"/></port>'
        '<port protocol="tcp" portid="80"><state state="closed"/></port>'
        "</ports></host></nmaprun>"
    ).encode()


def test_parse_open_port_and_service() -> None:
    result = parse_nmap_xml(scan(), "127.0.0.1")
    assert result.open_tcp_ports == frozenset({22})
    assert result.ports[0].service == "ssh"
    assert result.ports[0].version == "9.2"


def test_reject_unexpected_target() -> None:
    with pytest.raises(NmapParseError, match="outside"):
        parse_nmap_xml(scan("127.0.0.2"), "127.0.0.1")


def test_reject_doctype_and_large_xml() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(
            b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>',
            "127.0.0.1",
        )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"x" * 2_000_001, "127.0.0.1")


def test_reject_malformed_xml() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(b"<nmaprun>", "127.0.0.1")


def test_accept_real_nmap_empty_doctype():
    content = b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n' + scan()
    assert parse_nmap_xml(content, "127.0.0.1").open_tcp_ports == frozenset({22})


@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE nmaprun SYSTEM "https://outside.invalid/nmap.dtd">',
        '<!DOCTYPE nmaprun [<!ENTITY port "22">]>',
        "<!DOCTYPE nmaprun><!DOCTYPE nmaprun>",
    ],
)
def test_reject_nonempty_or_duplicate_doctype(declaration):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(declaration.encode() + scan(), "127.0.0.1")


def test_reject_utf16_entity_bypass():
    content = '<!DOCTYPE nmaprun [<!ENTITY port "22">]><nmaprun/>'
    with pytest.raises(NmapParseError):
        parse_nmap_xml(content.encode("utf-16"), "127.0.0.1")


@pytest.mark.parametrize(
    "content",
    [
        scan().replace(b"<host>", b'<host timedout="true">'),
        b'<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
    ],
)
def test_incomplete_nmap_xml_cannot_be_a_success(content):
    with pytest.raises(NmapParseError, match="incomplete"):
        parse_nmap_xml(content, "127.0.0.1")


def test_network_host_and_service_metadata():
    xml = (
        scan()
        .replace(b"<host>", b'<host><status state="up" reason="user-set"/>')
        .replace(
            b'version="9.2"',
            b'version="9.2" product="OpenSSH" tunnel="ssl" method="probed" conf="10"',
        )
    )
    result = parse_nmap_xml(xml, "127.0.0.1", (22, 80))
    assert result.host_state == "up" and result.host_reason == "user-set"
    assert result.ports[0].product == "OpenSSH"
    assert result.ports[0].service_method == "probed"
    assert result.ports[0].service_confidence == 10
    assert result.ports[0].tunnel == "ssl"


def test_exact_aggregate_closed_ports_and_ambiguous_missing_ports():
    xml = scan().replace(
        b'<port protocol="tcp" portid="80"><state state="closed"/></port>',
        b'<extraports state="closed" count="2"/>',
    )
    result = parse_nmap_xml(xml, "127.0.0.1", (22, 80, 443))
    assert {(p.port, p.state) for p in result.ports} == {
        (22, "open"),
        (80, "closed"),
        (443, "closed"),
    }
    # A count mismatch does not make any unknown port closed.
    assert len(parse_nmap_xml(xml, "127.0.0.1", (22, 80)).ports) == 1
    assert not parse_nmap_xml(b"<nmaprun/>", "127.0.0.1", (80,)).ports


@pytest.mark.parametrize(
    "xml,ports",
    [
        (scan(), (80,)),
        (
            scan().replace(b"</ports>", b'<port protocol="tcp" portid="22"/></ports>'),
            (22, 80),
        ),
        (scan().replace(b"</nmaprun>", scan().split(b"<nmaprun>")[1]), (22, 80)),
        (scan().replace(b'version="9.2"', b'conf="11"'), (22, 80)),
    ],
)
def test_reject_ambiguous_or_unrequested_network_observations(xml, ports):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(xml, "127.0.0.1", ports)
