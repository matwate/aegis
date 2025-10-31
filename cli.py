from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional

import typer

from safety import geneate_keypair, encrypt_directive, decrypt_directive
from model import AutorunFile
from pydantic_yaml import parse_yaml_file_as

import usb_utils as usb
import run as autorun_runner

app = typer.Typer(
    add_completion=False,
    help="""
Aegis: USB autorun model tool

Commands:
  generate-keypair  Create RSA keys (public/private)
  encode            Encrypt a YAML manifest and copy to USB
  validate          Decrypt + parse manifest from USB to verify
  daemon            Listen for USB and execute autorun if valid

Quickstart:
  python cli.py generate-keypair
  python cli.py encode default.yaml
  python cli.py validate
  python cli.py daemon

Tip: Use --help on any command for options and examples.
""",
)

DEFAULT_ENC_NAME = "aegis.enc"
DEFAULT_PUBLIC_KEY = "aegis_public_key.pem"
DEFAULT_PRIVATE_KEY = "private_key.pem"


@app.command("generate-keypair")
def generate_keypair(bits: int = typer.Option(2048, help="RSA key size in bits")):
    """Generate or reuse a private key, and write/update the public key.

    Examples:
      python cli.py generate-keypair
      python cli.py generate-keypair --bits 4096
    """
    geneate_keypair(size=bits)
    typer.echo("Keys ready: private_key.pem, aegis_public_key.pem")


@app.command()
def encode(
    manifest: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to YAML manifest"
    ),
    public_key: Path = typer.Option(
        Path(DEFAULT_PUBLIC_KEY), exists=True, readable=True, help="Path to public key"
    ),
    enc_name: str = typer.Option(
        DEFAULT_ENC_NAME, help="Filename to write on the USB drive"
    ),
    usb_timeout: Optional[float] = typer.Option(
        120.0, help="Timeout in seconds to wait for a USB drive (None = forever)"
    ),
    udisksctl_only: bool = typer.Option(
        False, help="Only use udisksctl for mounting (no sudo fallback)"
    ),
):
    """Encrypt MANIFEST and place it on a plugged USB drive.

    Examples:
      python cli.py encode default.yaml
      python cli.py encode default.yaml --public-key aegis_public_key.pem
      python cli.py encode default.yaml --enc-name custom.enc --usb-timeout 300

    Notes:
      - Uses hybrid encryption (AES-256-GCM for data + RSA-OAEP for the key),
        so manifest size is not limited by RSA.
      - Writes the encrypted blob to a temporary file and then copies it to USB
        (no artifacts left in the repo, avoids permission issues).
      - If no USB is plugged in, the command waits until one is mounted
        (or until the timeout elapses if provided).
      - The encrypted file name defaults to aegis.enc on the USB drive.
    """
    typer.echo(f"Encrypting manifest: {manifest}")
    tmp_dir = tempfile.mkdtemp(prefix="aegis_")
    enc_tmp = Path(tmp_dir) / "manifest.enc"
    enc_local_path = encrypt_directive(str(manifest), str(public_key), str(enc_tmp))

    mount_point: Optional[str] = None
    try:
        typer.echo("Please plug in a USB drive... waiting to mount")
        mount_point = usb.wait_for_usb_mount(timeout=usb_timeout, udisksctl_only=udisksctl_only)
        if not mount_point:
            typer.secho("Timed out waiting for USB drive.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        target = Path(mount_point) / enc_name
        shutil.copy2(enc_local_path, target)
        typer.secho(f"Encrypted file copied to {target}", fg=typer.colors.GREEN)
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
        if mount_point:
            usb.unmount_device(mount_point)


@app.command()
def validate(
    private_key: Path = typer.Option(
        Path(DEFAULT_PRIVATE_KEY),
        exists=True,
        readable=True,
        help="Path to private key for validation",
    ),
    enc_name: str = typer.Option(
        DEFAULT_ENC_NAME, help="Encrypted filename to check on USB"
    ),
    usb_timeout: Optional[float] = typer.Option(
        120.0, help="Timeout in seconds to wait for a USB drive (None = forever)"
    ),
    udisksctl_only: bool = typer.Option(
        False, help="Only use udisksctl for mounting (no sudo fallback)"
    ),
):
    """Verify the encrypted manifest on a USB drive can be decrypted and parsed.

    Examples:
      python cli.py validate
      python cli.py validate --private-key private_key.pem --enc-name aegis.enc
    """
    typer.echo("Waiting for a USB drive to validate...")
    mount_point = usb.wait_for_usb_mount(timeout=usb_timeout, udisksctl_only=udisksctl_only)
    if not mount_point:
        typer.secho("Timed out waiting for USB drive.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    enc_path = Path(mount_point) / enc_name
    if not enc_path.is_file():
        usb.unmount_device(mount_point)
        typer.secho(f"Encrypted file not found: {enc_path}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    tmp_dir = tempfile.mkdtemp(prefix="aegis_")
    dec_path = Path(tmp_dir) / "manifest.dec.yaml"

    try:
        decrypt_directive(str(enc_path), str(private_key), str(dec_path))
        parse_yaml_file_as(AutorunFile, str(dec_path))
        typer.secho(
            "Validation successful: manifest decrypts and parses.",
            fg=typer.colors.GREEN,
        )
    finally:
        usb.unmount_device(mount_point)
        try:
            if dec_path.exists():
                dec_path.unlink()
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


@app.command()
def daemon(
    private_key: Path = typer.Option(
        Path(DEFAULT_PRIVATE_KEY),
        exists=True,
        readable=True,
        help="Path to private key for decryption",
    ),
    enc_name: str = typer.Option(
        DEFAULT_ENC_NAME, help="Encrypted filename to execute"
    ),
    udisksctl_only: bool = typer.Option(
        False, help="Only use udisksctl for mounting (no sudo fallback)"
    ),
):
    """Listen for USB drives and autorun if the encrypted manifest is valid.

    Examples:
      python cli.py daemon
      python cli.py daemon --private-key private_key.pem --enc-name aegis.enc

    Behavior:
      - Watches for new USB mass-storage devices.
      - Mounts, decrypts the encrypted file, validates the manifest schema,
        then invokes the autorun handler if valid.
    """
    import pyudev
    import time

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    # Preflight: warn if udisksctl is unavailable and user requested non-sudo usage
    try:
        import usb_utils as _usb
        if udisksctl_only and not _usb.have_udisksctl():
            typer.secho(
                "udisksctl not found on PATH. Install 'udisks2' package to use non-sudo mounting.",
                fg=typer.colors.YELLOW,
            )
    except Exception:
        pass

    typer.secho("Aegis daemon listening for USB drives...", fg=typer.colors.CYAN)

    for device in iter(monitor.poll, None):
        try:
            if device.action != "add":
                continue
            if device.device_type != "disk":
                continue
            # Detect USB ancestry without deprecated find_parent
            try:
                parent_is_usb = False
                p = device
                while p is not None:
                    if p.subsystem == "usb":
                        parent_is_usb = True
                        break
                    p = p.parent
                if not parent_is_usb:
                    continue
            except Exception:
                continue
            node = device.device_node
            if not node:
                continue

            parts = usb.wait_for_partitions(node)
            targets = parts if parts else [node]
            mount_point: Optional[str] = None
            for target in targets:
                mp = usb.mount_device(target, udisksctl_only=udisksctl_only)
                if mp:
                    mount_point = mp
                    break
            if not mount_point:
                continue

            enc_path = Path(mount_point) / enc_name
            if not enc_path.is_file():
                usb.unmount_device(mount_point)
                continue

            tmp_dir = tempfile.mkdtemp(prefix="aegis_")
            dec_path = Path(tmp_dir) / "manifest.dec.yaml"
            try:
                decrypt_directive(str(enc_path), str(private_key), str(dec_path))
                model = parse_yaml_file_as(AutorunFile, str(dec_path))
                typer.secho(
                    f"Valid manifest found on {mount_point}; executing autorun...",
                    fg=typer.colors.GREEN,
                )
                autorun_runner.autorun(model, mount_point)
                typer.secho(
                    f"Autorun completed for device at {mount_point}",
                    fg=typer.colors.GREEN,
                )
            except Exception as e:
                typer.secho(
                    f"Manifest invalid on {mount_point}: {e}", fg=typer.colors.RED
                )
            finally:
                try:
                    if dec_path.exists():
                        dec_path.unlink()
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass
                usb.unmount_device(mount_point)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            typer.secho(f"Error processing device: {e}", fg=typer.colors.RED)
            time.sleep(0.5)


def main():
    app()


if __name__ == "__main__":
    main()
