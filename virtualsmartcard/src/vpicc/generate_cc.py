import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
import json
from binascii import b2a_base64
import datetime
import uuid
from enum import Enum
import argparse

class CCGenerator():
    class KeyUsage(Enum):
        DIGITAL_SIGNATURE = 1
        NON_REPUDIATION = 2
    
    class CertificateType(Enum):
        ROOT = 1
        USER = 2

    def __init__(self):
        self.fs_paths = {}
        self.fs_paths["sign_key"] = "sign-private-key"
        self.fs_paths["auth_key"] = "auth-private-key"

        self.setPaths()

    def setPaths(self):
        self.fs_paths["cert_auth"] = "3f00-5f00-ef09"
        self.fs_paths["cert_sign"] = "3f00-5f00-ef08"
        self.fs_paths["cert_root"] = "3f00-5f00-ef11"
        self.fs_paths["cert_root_auth"] = "3f00-5f00-ef10"
        self.fs_paths["cert_root_sign"] = "3f00-5f00-ef0f"

    def generatePrivateKey(self, certificate_type):
        if certificate_type == CCGenerator.CertificateType.ROOT:
            return rsa.generate_private_key(65537, 4096, default_backend())
        elif certificate_type == CCGenerator.CertificateType.USER:
            return rsa.generate_private_key(65537, 3072, default_backend())

    def generate_ec(self, subject, start_date = None, end_date = None, issuer = None, signing_key = None):
        # Generate our key
        private_key = self.generatePrivateKey(CCGenerator.CertificateType.ROOT)

        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        b = builder.subject_name(subject)

        if issuer is None:
            issuer = subject # self-signed
        b = b.issuer_name(issuer)

        if start_date is None:
            start_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        if end_date is None:
            end_date = datetime.datetime.utcnow() + datetime.timedelta(days=365 * 15)
        b = b.not_valid_before(start_date)
        b = b.not_valid_after(end_date)

        b = b.serial_number(int(uuid.uuid4()))
        b = b.public_key(public_key)
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        b = b.add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False),
            critical=False
        )

        if signing_key is None:
            signing_key = private_key # self-signed
        certificate = b.sign(
            private_key=signing_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate, private_key

    def generate_user_certificate(self, subject, key_usage, issuer, signing_key, start_date = None, end_date = None):
        # Generate our key
        private_key = self.generatePrivateKey(CCGenerator.CertificateType.USER)

        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        b = builder.subject_name(subject)
        b = b.issuer_name(issuer)

        if start_date is None:
            start_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        if end_date is None:
            end_date = datetime.datetime.utcnow() + datetime.timedelta(days=365 * 15)
        b = b.not_valid_before(start_date)
        b = b.not_valid_after(end_date)

        b = b.serial_number(int(uuid.uuid4()))
        b = b.public_key(public_key)
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        b = b.add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=key_usage | CCGenerator.KeyUsage.DIGITAL_SIGNATURE.value,
                content_commitment=key_usage | CCGenerator.KeyUsage.NON_REPUDIATION.value,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False),
            critical=False
        )

        certificate = b.sign(
            private_key=signing_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate, private_key

class CC2Generator(CCGenerator):
    def __init__(self):
        super().__init__()
    
    def setPaths(self):
        self.fs_paths["cert_auth"] = "3f00-604632ff000004-5f00-ef02"
        self.fs_paths["cert_sign"] = "3f00-604632ff000004-5f00-ef04"
        self.fs_paths["cert_root"] = "3f00-604632ff000004-5f00-ef0a"
        self.fs_paths["cert_root_auth"] = "3f00-604632ff000004-5f00-ef06"
        self.fs_paths["cert_root_sign"] = "3f00-604632ff000004-5f00-ef08"

    def generatePrivateKey(self, certificate_type):
        if certificate_type == CCGenerator.CertificateType.ROOT:
            return ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif certificate_type == CCGenerator.CertificateType.USER:
            return ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    def generate_ec(self, subject, start_date=None, end_date=None, issuer=None, signing_key=None):
        return super().generate_ec(subject, start_date, end_date, issuer, signing_key)
    
    def generate_user_certificate(self, subject, key_usage, issuer, signing_key, start_date=None, end_date=None):
        return super().generate_user_certificate(subject, key_usage, issuer, signing_key, start_date, end_date)

def generateJson(user_auth, user_auth_private_key, user_sign, user_sign_private_key, ec_cc, ec_auth, ec_sign):
    data = {}
    data[generator.fs_paths["cert_auth"]] = {'data': b2a_base64(user_auth.public_bytes(encoding=serialization.Encoding.DER)),
                            'fci': b2a_base64(b'\x8C\x05\x1B\xFF\xFF\xFF\x00')}

    data["auth-private-key"] = {'data': b2a_base64(user_auth_private_key.private_bytes(encoding=serialization.Encoding.DER,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption()))}

    data[generator.fs_paths["cert_sign"]]  = {'data': b2a_base64(user_sign.public_bytes(encoding=serialization.Encoding.DER)),
                            'fci': b2a_base64(b'\x8C\x05\x1B\xFF\x00\xFF\x00')}

    data["sign-private-key"] = {'data': b2a_base64(user_sign_private_key.private_bytes(encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))}

    data[generator.fs_paths["cert_root"]]  = {'data': b2a_base64(ec_cc.public_bytes(encoding=serialization.Encoding.DER)),
                            'fci': b2a_base64(b'\x8C\x05\x1B\xFF\x00\xFF\x00')}


    data[generator.fs_paths["cert_root_auth"]] = {'data': b2a_base64(ec_auth.public_bytes(encoding=serialization.Encoding.DER)),
                            'fci': b2a_base64(b'\x8C\x05\x1B\xFF\x00\xFF\x00')}

    data[generator.fs_paths["cert_root_sign"]]  = {'data': b2a_base64(ec_sign.public_bytes(encoding=serialization.Encoding.DER)),
                            'fci': b2a_base64(b'\x8C\x05\x1B\xFF\x00\xFF\x00')}

    for k in data:
        for kk in data[k]:
            if isinstance(data[k][kk], bytes):
                data[k][kk] = data[k][kk].decode().strip()
    
    return data

def export_certificate(file_name, cert):
    with open(file_name, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

parser = argparse.ArgumentParser()
parser.add_argument('--pteid_version',
    required=True,
    action="store",
    choices=['cc1', 'cc2'],
    default='cc1',
    help='Choose between identity card v1 or v2')

parser.add_argument("-i", "--input",
    action="store",
    help="Input file with the card data")

parser.add_argument("-o", "--output",
    action="store",
    help="Output file with the card data")

parser.add_argument("-r", "--export-root",
    action="store",
    help="Export the root certificate and private key")

args = parser.parse_args()
pteid_version = args.pteid_version
input_file = args.input
output_file = args.output

if not input_file:
    input_file = "cc1_base.json" if pteid_version == 'cc1' else "cc2_base.json"

if not output_file:
    output_file = "card.json"

json_data = {}
if input_file and not os.path.exists(input_file):
    print("Input file does not exist")
    exit(1)

try:
    with open(input_file, 'r') as f:
        json_data = json.load(f)
except Exception as e:
    json_data = {}

generator = CCGenerator() if pteid_version == 'cc1' else CC2Generator()
# Generate the CA certificate
force_create = True
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        u'SCEE - Sistema de Certificação Electrónica do Estado VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'ECEstado VIRTUAL'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'PT')
])
ec_cc, ec_cc_private_key = generator.generate_ec(subject)

# export root certificate
if (args.export_root):
    export_certificate(args.export_root, ec_cc)

# Generate EC Authentication certificate
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME,
                        u'EC de Autenticação do Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        u'Instituto dos Registos e do Notariado I.P. VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'subECEstado VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'PT')
])
ec_auth, ec_auth_private_key = generator.generate_ec(subject, None, None, ec_cc.subject, ec_cc_private_key)

# Generate User Authentication certificate
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'PAULO VIRTUAL'),
    x509.NameAttribute(NameOID.SERIAL_NUMBER, u'BI123123123'),
    x509.NameAttribute(NameOID.SURNAME, u'VIRTUAL'),
    x509.NameAttribute(NameOID.GIVEN_NAME, u'PAULO'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        u'Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Cidadão Português VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Autenticação do Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'PT')
])
user_auth, user_auth_private_key = generator.generate_user_certificate(subject, CCGenerator.KeyUsage.NON_REPUDIATION.value, ec_auth.subject, ec_auth_private_key)

# Generate User Signature certificate
subject = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME, u'EC de Assinatura Digital Qualificada do Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        u'Instituto dos Registos e do Notariado I.P. VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'subECEstado VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'PT')
])
ec_sign, ec_sign_private_key = generator.generate_ec(subject, None, None, ec_cc.subject, ec_cc_private_key)

# Generate User Signature certificate
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'PAULO VIRTUAL'),
    x509.NameAttribute(NameOID.SERIAL_NUMBER, u'BI123123123'),
    x509.NameAttribute(NameOID.SURNAME, u'VIRTUAL'),
    x509.NameAttribute(NameOID.GIVEN_NAME, u'PAULO'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        u'Cartão de Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Cidadão Português VIRTUAL'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                        u'Assinatura Qualificada do Cidadão VIRTUAL'),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u'PT')
])
user_sign, user_sign_private_key = generator.generate_user_certificate(subject, CCGenerator.KeyUsage.DIGITAL_SIGNATURE.value, ec_sign.subject, ec_sign_private_key)

json_data.update(generateJson(user_auth, user_auth_private_key, user_sign, user_sign_private_key, ec_cc, ec_auth, ec_sign))

with open(output_file, 'w') as f:
    json.dump(json_data, f, indent=4)