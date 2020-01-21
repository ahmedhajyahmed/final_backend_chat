import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


class CA:

    @staticmethod
    def load_client_csr(path):
        pem_csr = open(path, 'rb').read()
        try:
            csr = x509.load_pem_x509_csr(pem_csr, default_backend())
        except Exception:
            raise Exception("CSR presented is not valid.")
        return csr

    @staticmethod
    def load_ca_crt(path):
        pem_cert = open(path, 'rb').read()
        ca = x509.load_pem_x509_certificate(pem_cert, default_backend())
        return ca

    @staticmethod
    def load_ca_private_key(path):
        pem_key = open(path, 'rb').read()
        ca_key = serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())
        return ca_key

    @staticmethod
    def sign(csr, path):

        ca_cert = CA.load_ca_crt('ca/ca.crt')
        ca_private_key = CA.load_ca_private_key('ca/ca.key')

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.not_valid_before(datetime.datetime.now() - datetime.timedelta(1))
        builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(7))  # days
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number((int(uuid.uuid4())))

        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(path + '/cert.crt', 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        return certificate
