import argparse, os, ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def ensure_dir(path:str):
    os.makedirs(path, exist_ok=True)

def write(path, data: bytes):
    ensure_dir(os.path.dirname(path))
    with open(path, "wb") as f:
        f.write(data)

def make_ca(common_name: str, days: int):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name + " CA")])
    now = datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    return ca_key, cert

def make_server_cert(ca_key, ca_cert, common_name: str, days: int):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1"))
    ])
    now = datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)\
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)\
            .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    return key, cert

def sha1_thumbprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    d = hashes.Hash(hashes.SHA1())
    d.update(der)
    return d.finalize().hex().upper()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cn", default="localhost")
    ap.add_argument("--days", type=int, default=3650)
    args = ap.parse_args()

    ensure_dir(args.out_dir)

    ca_key, ca_cert = make_ca(args.cn, args.days)
    server_key, server_cert = make_server_cert(ca_key, ca_cert, args.cn, args.days)

    write(os.path.join(args.out_dir, "ca.key.pem"), ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    write(os.path.join(args.out_dir, "ca.cert.pem"), ca_cert.public_bytes(serialization.Encoding.PEM))
    write(os.path.join(args.out_dir, "localhost.key.pem"), server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    write(os.path.join(args.out_dir, "localhost.cert.pem"), server_cert.public_bytes(serialization.Encoding.PEM))

    with open(os.path.join(args.out_dir, "ca_thumbprint.txt"), "w", encoding="utf-8") as f:
        f.write(sha1_thumbprint(ca_cert))

    print("CA + Server-Zertifikat erstellt unter:", args.out_dir)

if __name__ == "__main__":
    main()
