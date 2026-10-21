
# Requer: pip install cryptography

import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

def nome(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def agora():
    return datetime.datetime.now(datetime.timezone.utc)


def key_usage(**ativos):
    campos = dict(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    campos.update(ativos)
    return x509.KeyUsage(**campos)


def gerar_certificado_raiz():
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nome("AC Raiz"))
        .issuer_name(nome("AC Raiz"))
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora() - datetime.timedelta(minutes=1))
        .not_valid_after(agora() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .sign(chave, hashes.SHA256())
    )
    return chave, cert


def gerar_certificado_servidor(ca_chave, ca_cert, cn, dias=365):
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nome(cn))
        .issuer_name(ca_cert.subject)
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora() - datetime.timedelta(minutes=1))
        .not_valid_after(agora() + datetime.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            key_usage(digital_signature=True, key_encipherment=True), critical=True
        )
        .sign(ca_chave, hashes.SHA256())
    )
    return chave, cert


class Servidor:
    def __init__(self, cert, chave):
        self.cert = cert
        self._chave = chave  # PrivSVR nunca sai do servidor

    def hello(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def responder_desafio(self, cifrado):
        return self._chave.decrypt(cifrado, OAEP)


class Cliente:
    def __init__(self, ca_cert, hostname_esperado):
        self.ca_cert = ca_cert
        self.hostname = hostname_esperado

    def validar_certificado(self, pem):
        cert = x509.load_pem_x509_certificate(pem)

        # 1. Assinatura da CA
        if cert.issuer != self.ca_cert.subject:
            raise ValueError("Emissor não confiável")
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            raise ValueError("Assinatura do certificado inválida")

        # 2. Prazo de validade
        t = agora()
        if not (cert.not_valid_before_utc <= t <= cert.not_valid_after_utc):
            raise ValueError("Certificado fora do prazo de validade")

        # Uso da chave: precisa permitir cifrar (o nonce é cifrado com PubSVR)
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            raise ValueError("Certificado sem KeyUsage")
        if not ku.key_encipherment:
            raise ValueError("Certificado não permite key_encipherment")

        # 3. Identidade (CN)
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cns) != 1 or cns[0].value != self.hostname:
            raise ValueError(f"CN não corresponde a {self.hostname!r}")

        # 4. Extrai PubSVR
        return cert.public_key()

    def autenticar(self, servidor):
        pem = servidor.hello()
        try:
            pub = self.validar_certificado(pem)
        except ValueError as e:
            print(f"Cliente: certificado rejeitado ({e})")
            return False

        nonce = os.urandom(32)
        print(f"Cliente: Nonce gerado = {nonce.hex()}")
        resposta = servidor.responder_desafio(pub.encrypt(nonce, OAEP))
        print(f"Servidor -> Cliente: Nonce = {resposta.hex()}")
        return resposta == nonce


def main():
    host = "servidor.exemplo.com"
    ca_chave, ca_cert = gerar_certificado_raiz()
    sv_chave, sv_cert = gerar_certificado_servidor(ca_chave, ca_cert, host)

    # Certificado falso
    fk, fc = gerar_certificado_raiz()
    fsk, fsc = gerar_certificado_servidor(fk, fc, host)

    print("=== Cenário 1: servidor legítimo ===")
    def resultado(ok):
        print("Autenticação:", "SUCESSO" if ok else "FALHA")

    print("=== Cenário 1: servidor legítimo ===")
    resultado(Cliente(ca_cert, host).autenticar(Servidor(sv_cert, sv_chave)))

if __name__ == "__main__":
    main()
