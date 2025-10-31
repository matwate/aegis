Aegis: USB autorun model tool

Overview:
- Encrypts an autorun manifest (YAML), copies it to a USB drive, and verifies signatures before executing.
- Uses hybrid encryption (AES-256-GCM + RSA-OAEP) for the manifest.
- Signs metadata that includes the encrypted blob hash, and when provides_file is true, the actual file hash on the USB.
- Daemon validates signatures and refuses to run if the USB file was tampered.

Commands:
- generate-keypair: Create RSA keys (public/private)
- encode: Encrypt a YAML manifest and copy to USB (writes aegis.meta.json)
- validate: Verify signature, decrypt + parse manifest from USB
- daemon: Listen for USB and execute autorun if valid

Quickstart:
- python cli.py generate-keypair
- python cli.py encode examples/usb_script.yaml
- python cli.py validate
- python cli.py daemon

Security model:
- Metadata `aegis.meta.json` contains:
  - version, signer_key_id, enc_sha256, optional file_sha256, sig_b64
- Signature covers: `AEGISv1|enc_sha256=<hex>|file_sha256=<hex|empty>`
- If the manifest sets `provides_file: true`, encode computes and signs the hash of that specific file on the USB.
- validate/daemon: verify metadata; if provides_file, require a signed file hash and re-verify against the file on the USB before execution.
- run: enforces the file hash at execution time.

Usage notes:
- `--public-key` selects the public key to encrypt with and verify against.
- encode signs with `private_key.pem` by default; we can add `--private-key` if needed.
- Use `--udisksctl-only` to avoid sudo fallback for mounting (requires `udisksctl`).

Examples:
- See `examples/` and its README for concrete scenarios (logger, write tmp file, USB script).
