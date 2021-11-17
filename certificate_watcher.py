#!/usr/bin/env python3

"""Prints (on stderr) the list and expiration time ssl certificats of
all given domains like:

   ./warn_expire.py mdk.fr python.org duckduckgo.com
   mdk.fr expire in 2 days

"""

import argparse
import collections
from datetime import datetime, timedelta
import re
import socket
import ssl


__version__ = "0.0.5"


Context = collections.namedtuple('Context', ['now', 'limit', 'verbose'])


def get_server_certificate(service, timeout=10):
    """Retrieve the certificate from the server at the specified address" """
    context = ssl.create_default_context()
    with socket.create_connection(
        (service.ip or service.hostname, service.port), timeout
    ) as sock:
        with context.wrap_socket(sock, server_hostname=service.hostname) as sslsock:
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


class Service:
    SPEC = "(?P<ip>@[^@:]+)|(?P<port>:[^@:]+)|(?P<hostname>[^@:]+)"

    def __init__(self, description):
        self.description = description
        self.ip = None
        self.port = 443
        self.hostname = None
        for token in re.finditer(Service.SPEC, description):
            kind = token.lastgroup
            value = token.group()
            if kind == "ip":
                self.ip = value[1:]
            if kind == "port":
                self.port = int(value[1:])
            if kind == "hostname":
                self.hostname = value

    def __repr__(self):
        return self.description


def validate_certificate(context: Context, service: Service):
    try:
        cert = get_server_certificate(service)
    except socket.timeout:
        return f"{service}: connect timeout"
    except ConnectionResetError:
        return f"{service}: Connection reset"
    except Exception as err:
        return f"{service}: {err!s}"
    else:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT")
        expire_in = not_after - context.now
        if expire_in < context.limit or context.verbose:
            return (
                f"{service} expire in {expire_in.total_seconds() // 86400:.0f} days"
            )


def main():
    args = parse_args()
    hosts = args.hosts
    if args.from_file:
        hosts.extend(
            host.strip()
            for host in args.from_file.read().split("\n")
            if host and not host.startswith("#")
        )
        args.from_file.close()

    context = Context(
        now=datetime.utcnow(),
        limit=timedelta(days=14),
        verbose=args.verbose,
    )

    for service in map(Service, hosts):
        if error := validate_certificate(context, service):
            print(error)


if __name__ == "__main__":
    main()
