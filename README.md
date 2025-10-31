Aegis: USB autorun model tool

Commands:
- generate-keypair: Create RSA keys (public/private)
- encode: Encrypt a YAML manifest and copy to USB
- validate: Decrypt + parse manifest from USB to verify
- daemon: Listen for USB and execute autorun if valid

Quickstart:
- python cli.py generate-keypair
- python cli.py encode default.yaml
- python cli.py validate
- python cli.py daemon

Tips:
- Use --help on any command for options and examples
- Use --udisksctl-only to avoid sudo fallback for mounting (requires udisksctl)
- See examples/ for sample manifests to try