import os
import subprocess
import json
import time
from typing import Optional

import pyudev

BASE_MOUNT_DIR = "/mnt/usb_temp"


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


def wait_for_partitions(device_node: str, timeout: float = 5.0, interval: float = 0.25) -> list[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        parts = lsblk_partitions(device_node)
        if parts:
            return parts
        time.sleep(interval)
    return []


def mount_device(block_device: str) -> Optional[str]:
    os.makedirs(BASE_MOUNT_DIR, exist_ok=True)
    mount_point = os.path.join(BASE_MOUNT_DIR, os.path.basename(block_device))
    os.makedirs(mount_point, exist_ok=True)
    result = subprocess.run(["mount", block_device, mount_point], capture_output=True, text=True)
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
    subprocess.run(["umount", mount_point], check=False)
    try:
        os.rmdir(mount_point)
    except Exception:
        pass


def wait_for_usb_mount(timeout: Optional[float] = None) -> Optional[str]:
    """Wait for a USB disk, mount first available partition, return mount point.

    If no partition exists, try mounting the whole disk.
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
        # Wait for partitions and try to mount the first one
        parts = wait_for_partitions(node)
        targets = parts if parts else [node]
        for target in targets:
            mp = mount_device(target)
            if mp:
                return mp
    return None
