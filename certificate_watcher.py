#!/usr/bin/env python3

"""Prints (on stderr) the list and expiration time ssl certificats of
all given domains like:

   ./warn_expire.py mdk.fr python.org duckduckgo.com
   mdk.fr expire in 2 days

"""

import sys
import ssl
import socket
from datetime import datetime, timedelta


__version__ = "0.0.1"


def get_server_certificate(addr, port=443, timeout=10):
    """Retrieve the certificate from the server at the specified address"
    """
    context = ssl.create_default_context()
    with socket.create_connection((addr, port), timeout) as sock:
        with context.wrap_socket(sock, server_hostname=addr) as sslsock:
            return sslsock.getpeercert()


def main():
    verbose = '-v' in sys.argv
    hosts = [host for host in sys.argv[1:] if host != '-v']
    now = datetime.utcnow()
    limit = timedelta(days=14)
    for host in hosts:
        try:
            cert = get_server_certificate(host)
        except socket.timeout:
            print("{host}: connect timeout".format(host=host))
        except ConnectionResetError:
            print("{host}: Connection reset".format(host=host))
        except (ssl.CertificateError, socket.gaierror, ssl.SSLError, ConnectionRefusedError) as err:
            print("{host}: {err}".format(host=host, err=str(err)))
        else:
            not_after = datetime.strptime(cert['notAfter'],
                                        "%b %d %H:%M:%S %Y GMT")
            expire_in = not_after - now
            if expire_in < limit or verbose:
                print("{host} expire in {expire_in:.0f} days".format(
                    host=host,
                    expire_in=expire_in.total_seconds() // 86400))


if __name__ == '__main__':
    main()
