#!/usr/bin/env python3

"""Prints (on stderr) the list and expiration time ssl certificats of
all given domains like:

   ./warn_expire.py mdk.fr python.org duckduckgo.com
   mdk.fr expire in 2 days

"""

import argparse
import csv
import re
import socket
import ssl
import sys
from datetime import datetime, timedelta

from ocspchecker import ocspchecker

__version__ = "0.1"


def get_server_certificate(service, timeout=10):
    """Retrieve the certificate from the server at the specified address" """
    context = ssl.create_default_context()
    context.options &= ssl.CERT_REQUIRED
    context.check_hostname = True
    with socket.create_connection(service.address, timeout) as sock:
        with context.wrap_socket(sock, server_hostname=service.hostname) as sslsock:
            return sslsock.getpeercert()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="Certificate Watcher",
        description="Watch expiration of certificates of a bunch of websites.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Add OK lines if all tests are OK",
    )
    parser.add_argument(
        "--csv", "-c", action="store_true", help="Output as coma-separated values."
    )
    parser.add_argument(
        "--attention",
        "-a",
        action="store_true",
        help=r"Add '\a' in case of KO in order to generate beeps "
        "(depending of the terminal)",
    )
    parser.add_argument(
        "--check-ocsp",
        "-o",
        action="store_true",
        help="OCSP CRL check, time consuming, advance checks not supported currently",
    )
    parser.add_argument(
        "--low",
        "-l",
        default=15,
        type=int,
        help="Number of days before expiration considered as low (default 15 days)",
    )
    parser.add_argument(
        "--high",
        "-H",
        default=365,
        type=int,
        help="Number of days after validation considered as high (default 365 days)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        default=10.0,
        type=float,
        help="Number of seconds (real) before timeout (default 10.0 seconds)",
    )
    parser.add_argument(
        "-f",
        "--from-file",
        type=argparse.FileType("r"),
        help="Check host from this file (one per line)",
    )
    parser.add_argument("hosts", nargs="*", help="Hosts to check")
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__
    )
    return parser.parse_args()


class Service:
    """Represent a host or an host:port pair (port defaults to 443).

    Optionally the host:port pair can be augmented by an IP to bypass
    DNS resolution.

    The optional IP address is given prefixed by an `@`, this is usefull to
    poke multiple backends like:

        s1 = Service("example.com@10.1.0.1")
        s2 = Service("example.com@10.1.0.2")

    A domain name, to be resolved, can be used in this field too, like:

        s1 = Service("example.com@backend1.example.com")
        s2 = Service("example.com@backend2.example.com")

    The `@host` and `:port` have no specific order, both
    "example.com:443@127.0.0.1" and "example.com@127.0.0.1:443" are
    parsed equally.
    """

    SPEC = "(?P<ip>@[^@:]+)|(?P<port>:[^@:]+)|(?P<hostname>[^@:]+)"

    def __init__(self, description):
        self.description = description
        self.ip_addr = None
        self.port = 443
        self.hostname = None
        for token in re.finditer(Service.SPEC, description):
            kind = token.lastgroup
            value = token.group()
            if kind == "ip":
                self.ip_addr = value[1:]
            if kind == "port":
                self.port = int(value[1:])
            if kind == "hostname":
                self.hostname = value
        if self.hostname is None:
            raise ValueError("A service cannot have no hostname.")

    def __repr__(self):
        return self.description

    @property
    def address(self):
        """Return a 2-tuple (host, port).

        If ip is given, (ip, port) is returned instead.
        """
        return (self.ip_addr or self.hostname, self.port)


class CertificateValidationError(Exception):
    """Raised by validate_certificate on any certificate error."""


def validate_certificate(
    service: Service,
    limitlow: timedelta = timedelta(days=15),
    limithigh: timedelta = timedelta(days=365),
    check_ocsp: bool = False,
    timeout=10,
):
    """Check for a certificate validity on a remote host.

    Raises CertificateValidationError with a specific message if an
    issue is found.

    >>> validate_certificate(Service("mdk.fr"))
    """
    try:
        cert = get_server_certificate(service, timeout=timeout)
    except socket.timeout as err:
        raise CertificateValidationError("connect timeout") from err
    except ConnectionResetError as err:
        raise CertificateValidationError("Connection reset") from err
    except Exception as err:
        raise CertificateValidationError(str(err)) from err
    else:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y GMT")
        expire_in = not_after - datetime.utcnow()
        certificate_age = datetime.utcnow() - not_before
        if (
            bool(check_ocsp)
            and ocspchecker.get_ocsp_status(service.hostname, service.port)[2]
            == "OCSP Status: REVOKED"
        ):
            raise CertificateValidationError("OCSP Satus: REVOKED")
        if expire_in < limitlow:
            raise CertificateValidationError(
                f"Certificate expires in {expire_in.total_seconds() // 86400:.0f} days"
            )
        if certificate_age > limithigh:
            raise CertificateValidationError(
                "Certificate is too old (has been created "
                f"{certificate_age.total_seconds() // 86400:.0f} days ago)"
            )


def main():
    """Command-line tool (certificate_watcher) entry point."""
    args = parse_args()
    if args.csv > 0:
        writer = csv.writer(sys.stdout, delimiter=",")
        writer.writerow(["Service", "Status"])
    else:
        writer = csv.writer(sys.stdout, delimiter=":")
    if args.from_file:
        args.hosts.extend(
            host.strip()
            for host in args.from_file.read().split("\n")
            if host and not host.startswith("#")
        )
        args.from_file.close()

    for service in map(Service, args.hosts):
        try:
            validate_certificate(
                service,
                limitlow=timedelta(days=args.low),
                limithigh=timedelta(days=args.high),
                check_ocsp=args.check_ocsp,
                timeout=args.timeout,
            )
        except CertificateValidationError as error:
            writer.writerow([str(service), str(error)])
            if not args.csv and args.attention:
                print("\a")
        else:
            if args.verbose:
                writer.writerow([str(service), "OK"])


if __name__ == "__main__":
    main()
