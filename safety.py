import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from typing import Optional, Tuple


def geneate_keypair(size: int = 4096) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    file = Path("private_key.pem")
    if file.is_file():
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            assert isinstance(private_key, RSAPrivateKey)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
        )
    # Always (re)write private key to ensure presence on disk
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


def encrypt_directive(
    directive_path: str, pk_path: str, output_path: Optional[str] = None
) -> str:
    with open(directive_path, "rb") as file:
        directive_data = file.read()
    public_key_obj = serialization.load_pem_public_key(open(pk_path, "rb").read())
    if not isinstance(public_key_obj, RSAPublicKey):
        raise TypeError("Public key must be RSA")

    # Hybrid encryption: AES-256-GCM for data + RSA-OAEP for AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, directive_data, None)

    enc_key = public_key_obj.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # File format:
    # magic(4)="AEGH" | ver(1)=1 | rsa_len(2 BE) | rsa_ct | nonce(12) | aes_ct
    header = b"AEGH" + bytes([1]) + struct.pack(">H", len(enc_key))
    payload = header + enc_key + nonce + ciphertext

    if output_path is None:
        output_path = directive_path + ".enc"
    with open(output_path, "wb") as enc_file:
        enc_file.write(payload)
    return output_path


def decrypt_directive(
    encrypted_path: str, sk_path: str, output_path: Optional[str] = None
) -> str:
    with open(encrypted_path, "rb") as file:
        blob = file.read()
    private_key_obj = serialization.load_pem_private_key(
        open(sk_path, "rb").read(),
        password=None,
    )
    if not isinstance(private_key_obj, RSAPrivateKey):
        raise TypeError("Private key must be RSA")

    decrypted: bytes
    if blob.startswith(b"AEGH") and len(blob) > 7:
        # Hybrid format
        ver = blob[4]
        if ver != 1:
            raise ValueError("Unsupported encrypted file version")
        rsa_len = struct.unpack(">H", blob[5:7])[0]
        offset = 7
        enc_key = blob[offset : offset + rsa_len]
        offset += rsa_len
        nonce = blob[offset : offset + 12]
        offset += 12
        ciphertext = blob[offset:]

        aes_key = private_key_obj.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aesgcm = AESGCM(aes_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    else:
        # Legacy RSA-only format
        decrypted = private_key_obj.decrypt(
            blob,
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
