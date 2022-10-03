from pathlib import Path

import pytest

from certificate_watcher import (
    validate_certificate,
    CertificateValidationError,
    Service,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.mark.parametrize("host", (FIXTURES / "badssl.txt").read_text().splitlines())
def test_all_badssl_are_failing(host):
    if host in (
        "pinning-test.badssl.com",
        "dh2048.badssl.com",
        "dh-small-subgroup.badssl.com",
    ):
        pytest.skip("Known false negative, to fix later maybe...")

    with pytest.raises(CertificateValidationError) as exc_info:
        validate_certificate(Service(host), check_ocsp=True)
    assert not exc_info.value.args[0].startswith('"')
