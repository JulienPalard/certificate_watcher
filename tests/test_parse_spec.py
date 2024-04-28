from certificate_watcher import Service


def test_parse_only_service():
    s = Service("mdk.fr")
    assert s.port == 443
    assert s.hostname == "mdk.fr"
    assert s.ip_addr is None


def test_parse_service_with_port():
    s = Service("mdk.fr:465")
    assert s.port == 465
    assert s.hostname == "mdk.fr"
    assert s.ip_addr is None


def test_parse_service_with_ip():
    s = Service("mdk.fr@127.0.0.1")
    assert s.port == 443
    assert s.hostname == "mdk.fr"
    assert s.ip_addr == "127.0.0.1"


def test_parse_service_with_port_and_ip():
    s = Service("mdk.fr:465@127.0.0.1")
    assert s.port == 465
    assert s.hostname == "mdk.fr"
    assert s.ip_addr == "127.0.0.1"
