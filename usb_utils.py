import os
import subprocess
import json
import time
import shutil
from typing import Optional

import pyudev

BASE_MOUNT_DIR = "/mnt/usb_temp"


def _have_udisksctl() -> bool:
    return shutil.which("udisksctl") is not None


def have_udisksctl() -> bool:
    """Public helper to check for udisksctl availability."""
    return _have_udisksctl()


def _udevadm_settle(timeout_sec: int = 5) -> None:
    """Wait for udev to process pending events.

    Helps avoid races like: "Error looking up object for device" when calling
    udisksctl immediately after a device add event.
    """
    try:
        if shutil.which("udevadm") is not None:
            subprocess.run(
                ["udevadm", "settle", "-t", str(timeout_sec)],
                capture_output=True,
                text=True,
                check=False,
            )
    except Exception:
        # Best-effort only
        pass


def _find_mount_point(source: str) -> Optional[str]:
    try:
        res = subprocess.run(
            ["findmnt", "-n", "-o", "TARGET", source],
            capture_output=True,
            text=True,
            check=True,
        )
        mp = res.stdout.strip()
        return mp if mp else None
    except Exception:
        return None


def _find_source_for_target(target: str) -> Optional[str]:
    try:
        res = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "--target", target],
            capture_output=True,
            text=True,
            check=True,
        )
        src = res.stdout.strip()
        return src if src else None
    except Exception:
        return None


def get_drive_type_linux(device_name: str) -> str:
    try:
        result = subprocess.run(
            ["lsblk", "-d", "-o", "ROTA", "-n", f"/dev/{device_name}"],
            capture_output=True,
            text=True,
            check=True,
        )
        rota_value = result.stdout.strip()
        return "HDD" if rota_value == "1" else "SSD/Flash"
    except subprocess.CalledProcessError:
        return "Unknown"
    except FileNotFoundError:
        return "lsblk not found"


def lsblk_partitions(device_node: str) -> list[str]:
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,TYPE,PATH", device_node],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        devs = data.get("blockdevices", [])
        if not devs:
            return []
        node = devs[0]
        parts = []
        for c in node.get("children", []) or []:
            if c.get("type") == "part" and c.get("path"):
                parts.append(c["path"])
        return parts
    except Exception:
        return []


def wait_for_partitions(
    device_node: str, timeout: float = 5.0, interval: float = 0.25
) -> list[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        parts = lsblk_partitions(device_node)
        if parts:
            return parts
        time.sleep(interval)
    return []


def mount_device(block_device: str, udisksctl_only: bool = False) -> Optional[str]:
    """Mount a block device and return the mount point.

    Prefers user-space mounting via udisksctl when available; otherwise falls back
    to creating a temporary mount under BASE_MOUNT_DIR (typically requires sudo).

    If udisksctl_only is True, skip the fallback and return None if udisksctl
    is unavailable or fails.
    """
    if _have_udisksctl():
        try:
            _udevadm_settle()
            print(f"[aegis] Attempting udisksctl mount of {block_device}...")
            res = subprocess.run(
                ["udisksctl", "mount", "-b", block_device],
                capture_output=True,
                text=True,
            )
            if res.stdout:
                print(res.stdout.strip())
            if res.stderr:
                print(res.stderr.strip())
            if res.returncode == 0:
                out = res.stdout.strip()

                # Expected: "Mounted /dev/sdXN at /run/media/$USER/LABEL."
                idx = out.rfind(" at ")
                if idx != -1:
                    mp = out[idx + 4 :].rstrip(".")
                    if os.path.isdir(mp):
                        print(f"[aegis] udisksctl mounted {block_device} at {mp}")
                        return mp
                mp = _find_mount_point(block_device)
                if mp:
                    print(f"[aegis] udisksctl mounted {block_device} at {mp} (via findmnt)")
                    return mp
            else:
                msg = res.stderr.strip() or res.stdout.strip() or "unknown error"
                print(f"[aegis] udisksctl mount failed for {block_device} (code {res.returncode}): {msg}")
        except Exception as e:
            print(f"[aegis] Exception during udisksctl mount for {block_device}: {e}")
        if udisksctl_only:
            print("[aegis] udisksctl_only=True; skipping fallback mount.")
            return None
    else:
        if udisksctl_only:
            print("[aegis] udisksctl not found on PATH; udisksctl_only=True => no mount attempt or fallback.")
            return None

    # Fallback to manual mount
    if udisksctl_only:
        print("[aegis] udisksctl not available or failed; udisksctl_only=True => no fallback.")
        return None
    os.makedirs(BASE_MOUNT_DIR, exist_ok=True)
    mount_point = os.path.join(BASE_MOUNT_DIR, os.path.basename(block_device))
    os.makedirs(mount_point, exist_ok=True)
    _udevadm_settle()
    result = subprocess.run(
        ["mount", block_device, mount_point], capture_output=True, text=True
    )
    if result.returncode != 0:
        try:
            subprocess.run(["umount", mount_point], check=False)
        finally:
            try:
                os.rmdir(mount_point)
            except Exception:
                pass
        return None
    return mount_point


def unmount_device(mount_point: str) -> None:
    """Unmount a previously mounted mount point.

    Uses udisksctl when present; otherwise falls back to umount. Cleans up
    temporary directories under BASE_MOUNT_DIR.
    """
    device = _find_source_for_target(mount_point)
    if device and _have_udisksctl():
        subprocess.run(["udisksctl", "unmount", "-b", device], check=False)
    else:
        subprocess.run(["umount", mount_point], check=False)
    try:
        if mount_point.startswith(BASE_MOUNT_DIR):
            os.rmdir(mount_point)
    except Exception:
        pass


def wait_for_usb_mount(
    timeout: Optional[float] = None, udisksctl_only: bool = False
) -> Optional[str]:
    """Wait for a USB disk, mount first available partition, return mount point.

    If no partition exists, try mounting the whole disk. Mounting uses udisksctl
    when available for non-root usage (subject to polkit), else falls back to
    root-style mounting under BASE_MOUNT_DIR. If udisksctl_only is True, the
    fallback is disabled and the function returns None if udisksctl cannot be used.
    """
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    start = time.time()
    for device in iter(monitor.poll, None):
        if timeout is not None and (time.time() - start) > timeout:
            return None
        if device.action != "add":
            continue
        if device.device_type != "disk":
            continue
        parent = device.find_parent("usb", "usb_device")
        if not parent:
            continue
        node = device.device_node
        if not node:
            continue
        parts = wait_for_partitions(node)
        targets = parts if parts else [node]
        for target in targets:
            mp = mount_device(target, udisksctl_only=udisksctl_only)
            if mp:
                return mp
    return None
