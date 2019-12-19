#!/usr/bin/env python3

"""Prints (on stderr) the list and expiration time ssl certificats of
all given domains like:

   ./warn_expire.py mdk.fr python.org duckduckgo.com
   mdk.fr expire in 2 days

"""

import argparse
from datetime import datetime, timedelta
import socket
import ssl
import sys


__version__ = "0.0.2"


def get_server_certificate(addr, port=443, timeout=10):
    """Retrieve the certificate from the server at the specified address"
    """
    context = ssl.create_default_context()
    with socket.create_connection((addr, port), timeout) as sock:
        with context.wrap_socket(sock, server_hostname=addr) as sslsock:
            return sslsock.getpeercert()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="Certificate Watcher",
        description="Watch expiration of certificates of a bunch of websites.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
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


def main():
    args = parse_args()
    hosts = args.hosts
    if args.from_file:
        hosts.extend(
            host.strip()
            for host in args.from_file.read().split("\n")
            if host and not host.startswith("#")
        )
    now = datetime.utcnow()
    limit = timedelta(days=14)
    for host in hosts:
        try:
            cert = get_server_certificate(host)
        except socket.timeout:
            print(f"{host}: connect timeout")
        except ConnectionResetError:
            print(f"{host}: Connection reset")
        except Exception as err:
            print(f"{host}: {err!s}")
        else:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
            expire_in = not_after - now
            if expire_in < limit or args.verbose:
                print(f"{host} expire in {expire_in.total_seconds() // 86400:.0f} days")


if __name__ == "__main__":
    main()
