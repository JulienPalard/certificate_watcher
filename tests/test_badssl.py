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
    with pytest.raises(CertificateValidationError):
        validate_certificate(Service(host))
