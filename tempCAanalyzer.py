import ssl
import socket
from OpenSSL import SSL, crypto

def fetch_certificate_chain(hostname, port=443):
    # Create SSL context
    context = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.connect((hostname, port))
    conn.set_tlsext_host_name(hostname.encode())

    # Perform handshake
    conn.do_handshake()

    # Get certificate chain
    cert_chain = conn.get_peer_cert_chain()
    conn.close()

    return cert_chain

def analyze_cert_chain(cert_chain):
    for i, cert in enumerate(cert_chain, start=1):
        print(f"\n=== Certificate {i} ===")
        subject = cert.get_subject()
        issuer = cert.get_issuer()

        print(f"Subject: {subject.CN}")
        print(f"Issuer: {issuer.CN}")
        print(f"Serial Number: {cert.get_serial_number()}")
        print(f"Version: {cert.get_version() + 1}")
        print(f"Not Before: {cert.get_notBefore().decode()}")
        print(f"Not After: {cert.get_notAfter().decode()}")

        # Public key details
        pub_key = cert.get_pubkey()
        key_type = pub_key.type()
        key_bits = pub_key.bits()
        print(f"Public Key Type: {key_type} ({'RSA' if key_type == crypto.TYPE_RSA else 'EC'})")
        print(f"Public Key Size: {key_bits} bits")

        # Extensions
        for j in range(cert.get_extension_count()):
            ext = cert.get_extension(j)
            print(f"Extension: {ext.get_short_name().decode()} - {ext}")

if __name__ == "__main__":
    hostname = input("Enter domain (e.g., example.com): ").strip()
    try:
        chain = fetch_certificate_chain(hostname)
        print(f"\nRetrieved {len(chain)} certificates from {hostname}")
        analyze_cert_chain(chain)
    except Exception as e:
        print(f"Error: {e}")
