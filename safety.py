from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from pathlib import Path


def geneate_keypair(size: int = 1024):

    file = Path("private_key.pem")
    if file.is_file():
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
        )
        with open("private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    public_key = private_key.public_key()
    with open("aegis_public_key.pem", "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_key, public_key


def encrypt_directive(directive_path: str, pk_path: str, output_path: str = None):
    public_key = None
    with open(directive_path, "rb") as file:
        directive_data = file.read()
        public_key = serialization.load_pem_public_key(open(pk_path, "rb").read())

        encrypted = public_key.encrypt(
            directive_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if output_path is None:
            output_path = directive_path + ".enc"
        with open(output_path, "wb") as enc_file:
            enc_file.write(encrypted)
    return output_path


def decrypt_directive(encrypted_path: str, sk_path: str, output_path: str = None):
    private_key = None
    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()
        private_key = serialization.load_pem_private_key(
            open(sk_path, "rb").read(),
            password=None,
        )

        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if output_path is None:
            output_path = encrypted_path.replace(".enc", ".dec")
        with open(output_path, "wb") as dec_file:
            dec_file.write(decrypted)
    return output_path
