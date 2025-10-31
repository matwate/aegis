# Aegis Examples

This folder contains example manifests to try with the CLI.

## How to use

1. Generate (or re-generate) keys. For larger manifests, 4096-bit is recommended:

```
python cli.py generate-keypair --bits 4096
```

2. Encrypt a manifest and copy to USB (insert if prompted):

```
python cli.py encode examples/logger.yaml
```

3. Run the daemon as root (mounting often requires root):

```
sudo .venv/bin/python cli.py daemon
```

4. Verify results depending on the example.

## Examples

- logger.yaml: writes to the system journal. Verify:
  - `journalctl -t aegis | tail`

- write_tmp_file.yaml: writes a file to /tmp. Verify:
  - `cat /tmp/aegis_example.txt`

- usb_script.yaml: runs a script located on the USB (`scripts/hello.sh`) using `/bin/bash`.
  - On the USB drive root, create `scripts/hello.sh` with executable bit:
    - `mkdir -p scripts`
    - `printf '#!/usr/bin/env bash\necho "Hello from USB!" | tee /tmp/aegis_usb_script.txt\n' > scripts/hello.sh`
    - `chmod +x scripts/hello.sh`


## Notes

- If encryption fails with size errors, either use 4096-bit keys or ask to switch to hybrid encryption.
- `.gitignore` excludes private keys and encrypted artifacts from Git.
