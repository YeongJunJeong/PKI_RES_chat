import rsa
import socket
import datetime
import sympy
import time
import binascii
from __future__ import unicode_literals
from math import sqrt
from Crypto.Random import random
random.randint(1, 10)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization
from RSA import gcd, egcd, modinverse, isprime, generate_prime, generate_keypair, encrypt, decrypt

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seoul"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seoul"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
])
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)


with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(Encoding.PEM))

with open("private_key.pem", "wb") as f:
    f.write(
        ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
    )



#CSR 처리 및 인증서 발급 (클라이언트 측 CSR 생성)

client_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# CSR 생성
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seoul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seoul"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Client"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"client.com"),
    ]))
    .sign(client_key, hashes.SHA256())
)

with open("client_csr.pem", "wb") as f:
    f.write(csr.public_bytes(Encoding.PEM))

# CA측에서 CSR 처리 및 인증서를 불러옴.
#CA의 개인키와 인증서를 불러옴.

with open("private_key.pem", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("certificate.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

with open("client_csr.pem", "rb") as f:
    client_csr = x509.load_pem_x509_csr(f.read())

client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_csr.subject)
    .issuer_name(ca_cert.subject)
    .public_key(client_csr.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"client.com")]),
        critical=False,
    )
    .sign(ca_private_key, hashes.SHA256())
)

with open("client_certificate.pem", "wb") as f:
    f.write(client_cert.public_bytes(Encoding.PEM))


#개인키 저장
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# 공개키/인증서 저장
with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

"""## **인증서 전송/검증**"""

#서버에서 클라이언트에게 인증서 전송
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 9999))
server_socket.listen()

# 클라이언트 연결 수락
client_socket, addr = server_socket.accept()

# 클라이언트에게 인증서 전송
client_socket.sendfile(open("certificate.pem", "rb"))

#클라리언트에서 인증서 검증

# 클라이언트에서 인증서를 받고 검증
server_cert = x509.load_pem_x509_certificate(server_cert_data)
# CA의 공개키를 사용하여 서버 인증서 검증 (여기서는 생략)

# CA의 공개키를 로드합니다.
with open("public_key.pem", "rb") as f:
    ca_public_key = serialization.load_pem_public_key(f.read())

# 검증하려는 인증서를 로드합니다.
with open("certificate.pem", "rb") as f:
    certificate = x509.load_pem_x509_certificate(f.read())

# 인증서의 서명을 CA의 공개키로 검증합니다.
try:
    ca_public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm
    )
    print("인증서가 유효합니다.")
except InvalidSignature:
    print("인증서가 유효하지 않습니다.")

"""## **암호화 통신**"""

#클라리언트 측에서 메세지 암호화
def send_encrypted_message(client_socket, public_key, message):
    encrypted_message = rsa.encrypt(public_key, message)
    client_socket.send(encrypted_message)

#서버 측에서 메세지 복호화
def receive_encrypted_message(client_socket, private_key):
    encrypted_message = client_socket.recv(1024)
    decrypted_message = rsa.decrypt(private_key, encrypted_message)
    return decrypted_message

#암호화 통신 클라이언트
# 서버의 공개키를 불러옵니다.
server_public_key = ...

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('172.16.0.108', 9999))

message = "안녕하세요"
send_encrypted_message(client_socket, server_public_key, message)

#암호화 통신 서버
# 서버의 개인키를 불러옵니다.
private_key = ...

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 9999))
server_socket.listen()

client_socket, addr = server_socket.accept()

decrypted_message = receive_encrypted_message(client_socket, private_key)
print("수신된 메시지:", decrypted_message)