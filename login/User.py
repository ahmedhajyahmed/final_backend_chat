import ast
import datetime
import hashlib
import os
import textwrap
import uuid

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask_jwt_extended import create_access_token
from ldap3 import Server, Connection, ALL

from CA import CA


def get_ldap_connection():
    server = Server('192.168.43.54:389', get_info=ALL)
    conn = Connection(server, 'cn=admin,dc=chatroom,dc=com', 'root', auto_bind=True)
    return conn


class User:

    @staticmethod
    def try_login(username, password):

        conn = get_ldap_connection()
        print('get connection')
        # conn.search('ou=Users,dc=example,dc=com', '(&(cn=%s)(userPassword=%s))' % (username, password))
        password = hashlib.sha256(password.encode()).hexdigest()
        conn.search('dc=chatroom,dc=com', '(&(cn=%s)(userPassword=%s))' % (username, password),
                    attributes=['userCertificate'])
        if conn.entries == []:
            return 'error not auth', 400
        else:
            result_str = conn.entries[0].entry_to_json()
            # print(json.loads(res.read()))
            result_dict = ast.literal_eval(result_str)
            cert_base64 = result_dict['attributes']['userCertificate;binary'][0]['encoded']
            print(cert_base64)
            cert_pem = _get_pem_from_der(cert_base64)
            print(cert_pem)
            certificate_obj = CA.verify(cert_pem)
            if certificate_obj is not None:
                subject = str(certificate_obj.get_subject()).split('CN=')[1].split('\'')[0]
                # issuer = str(certificate_obj.get_issuer())
                # pubkey = str(certificate_obj.get_pubkey())
                # algo = str(certificate_obj.get_signature_algorithm())
                print(subject)
                if subject == username:
                    print("username and the certificate subject are identical")
                    expires = datetime.timedelta(days=30)
                    access_token = create_access_token(identity=str(subject), expires_delta=expires)
                    return {'token': access_token}, 200
                return "username and the certificate subject are not identical", 400
            return 'invalid certificate', 400

    @staticmethod
    def try_signup(cn, givenName, sn, telephoneNumber, userPassword, userCertificateRequest):

        uid = generate_random_id()
        path = 'clients/' + uid + '-' + cn
        os.mkdir(path, 777)

        # print(uid)
        # print(path)

        private_key = generate_private_key()
        write_private_key(private_key, path=path)
        # csr = generate_and_write_csr(private_key=private_key,
        #                              COMMON_NAME=cn,
        #                              path=path)

        # print(userCertificateRequest)
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, userCertificateRequest)
        # csr = x509.load_pem_x509_csr(userCertificateRequest, default_backend())
        # pubkeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey())
        print(csr.get_subject())
        signed = CA.sign(csr, path)

        # file = open('cert.crt', 'rb').read()
        # pem_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, signed)
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, signed)
        # print(cert)
        conn = get_ldap_connection()

        conn.add('cn=%s,ou=myusers,dc=chatroom,dc=com' % cn, 'inetOrgPerson', {'givenName': givenName,
                                                                               'sn': sn,
                                                                               'telephoneNumber': telephoneNumber,
                                                                               'userPassword': hashlib.sha256(
                                                                                   userPassword.encode()).hexdigest(),
                                                                               'uid': uid,
                                                                               'userCertificate;binary': cert_der
                                                                               # 'userSMIMECertifcate': cert_der
                                                                               })
        # cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

        result = conn.result['description']
        if result == 'success':
            # print(conn.result.entry_to_json())
            return 'Success', 200
        else:
            return result, 400

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def write_private_key(private_key, path):
    with open(path + "/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))


def generate_and_write_csr(private_key, path, COMMON_NAME, COUNTRY_NAME="TN", STATE_OR_PROVINCE_NAME="TUNIS",
                           LOCALITY_NAME="TUNIS",
                           ORGANIZATION_NAME="GL", ):
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
            x509.DNSName(u"subdomain.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256(), default_backend())
    # Write our CSR out to disk.
    with open(path + "/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr


def generate_random_id():
    return str(uuid.uuid4())[:8]


def _get_pem_from_der(der):
    """
    Converts DER certificate to PEM.
    """
    return "\n".join(("-----BEGIN CERTIFICATE-----",
                      "\n".join(textwrap.wrap(der, 64)),
                      "-----END CERTIFICATE-----",))
