import os
import struct
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from typing import Optional, Tuple

import base64
import hashlib


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


# -------- Utilities for simple sign/verify metadata --------

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rsa_key_id_from_public_pem(pem_bytes: bytes) -> str:
    pub = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(pub, RSAPublicKey):
        raise TypeError("Public key must be RSA")
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def rsa_sign_pss_sha256(private_key_path: str, message: bytes) -> str:
    sk = serialization.load_pem_private_key(open(private_key_path, "rb").read(), password=None)
    if not isinstance(sk, RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    sig = sk.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def rsa_verify_pss_sha256(public_key_path: str, message: bytes, signature_b64: str) -> bool:
    try:
        pk = serialization.load_pem_public_key(open(public_key_path, "rb").read())
        if not isinstance(pk, RSAPublicKey):
            return False
        sig = base64.b64decode(signature_b64)
        pk.verify(
            sig,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def build_signing_message(enc_sha256: str, file_sha256: Optional[str]) -> bytes:
    fs = file_sha256 or ""
    msg = f"AEGISv1|enc_sha256={enc_sha256}|file_sha256={fs}"
    return msg.encode("utf-8")


def verify_metadata(enc_path: str, meta: dict, public_key_path: str, computed_file_sha256: Optional[str] = None) -> bool:
    try:
        if not isinstance(meta, dict):
            return False
        if int(meta.get("version", 0)) != 1:
            return False
        enc_hash = sha256_file(enc_path)
        if meta.get("enc_sha256") != enc_hash:
            return False
        # Use computed file hash if provided; else fall back to meta
        file_sha = computed_file_sha256 if computed_file_sha256 is not None else meta.get("file_sha256")
        message = build_signing_message(enc_hash, file_sha)
        sig_b64 = meta.get("sig_b64")
        if not isinstance(sig_b64, str) or not sig_b64:
            return False
        return rsa_verify_pss_sha256(public_key_path, message, sig_b64)
    except Exception:
        return False


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
