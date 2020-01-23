import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from OpenSSL import crypto


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
    def load_ca_crt():
        pem_cert = open('ca/ca.crt', 'rb').read()
        ca = x509.load_pem_x509_certificate(pem_cert, default_backend())
        return ca

    @staticmethod
    def load_ca_private_key(path):
        pem_key = open(path, 'rb').read()
        ca_key = serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())
        return ca_key

    @staticmethod
    def sign(csr, path):

        ca_cert = CA.load_ca_crt()
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

    @staticmethod
    def verify(cert_crt):
        # with open('client/cert.crt', 'r') as cert_file:
        #     cert = cert_file.read()

        # with open('./int-cert.pem', 'r') as int_cert_file:
        #     int_cert = int_cert_file.read()

        with open('ca/ca.crt', 'r') as root_cert_file:
            ca_crt = root_cert_file.read()

        trusted_certs = (ca_crt, ca_crt)
        verified, certificate = CA.verify_chain_of_trust(cert_crt, trusted_certs)

        if verified:
            print('Certificate verified')
        else:
            print('not verified')
        return certificate

    @staticmethod
    def verify_chain_of_trust(cert_pem, trusted_cert_pems):
        # traitement ici
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(store, certificate)
        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()

        if result is None:
            return True, certificate
        else:
            return False, None
