import os
import subprocess
import pyudev
import json
import time


def get_drive_type_linux(device_name):
    """Check if a drive is rotational (HDD) or not (SSD/Flash)."""
    try:
        command = ["lsblk", "-d", "-o", "ROTA", "-n", f"/dev/{device_name}"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        rota_value = result.stdout.strip()
        return "HDD" if rota_value == "1" else "SSD/Flash"
    except subprocess.CalledProcessError:
        return "Unknown"
    except FileNotFoundError:
        return "lsblk not found"


def lsblk_partitions(device_node):
    """Return list of partition device nodes for a disk (e.g., [/dev/sdb1, /dev/sdb2])."""
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


def wait_for_partitions(device_node, timeout=5.0, interval=0.25):
    """Poll for partitions to appear after a disk is added."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        parts = lsblk_partitions(device_node)
        if parts:
            return parts
        time.sleep(interval)
    return []


def main():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    for device in iter(monitor.poll, None):
        if device.action == "add":
            # Only consider top-level disks (not partitions)
            if device.device_type == "disk":
                # Check if the parent is USB
                parent = device.find_parent("usb", "usb_device")
                if parent:
                    node = device.device_node  # e.g., /dev/sdb
                    if not node:
                        continue
                    name = os.path.basename(node)

                    model = device.get("ID_MODEL", "Unknown")
                    vendor = device.get("ID_VENDOR", "Unknown")
                    drive_type = get_drive_type_linux(name)

                    print(
                        f"USB Drive detected:\n"
                        f"  Node: {node}\n"
                        f"  Vendor: {vendor}\n"
                        f"  Model: {model}\n"
                        f"  Type: {drive_type}"
                    )

                    # Wait briefly for partitions to appear
                    parts = wait_for_partitions(node)
                    if parts:
                        print(f"  Partitions detected: {', '.join(parts)}")
                        for p in parts:
                            check_For_encrypted_autoruns(p)
                    else:
                        print(
                            "  No partitions detected; attempting to mount the disk directly."
                        )
                        check_For_encrypted_autoruns(node)


def check_For_encrypted_autoruns(device_node):
    """Check for encrypted autorun files on the given block device (partition or whole disk)."""
    base_dir = "/mnt/usb_temp"
    mount_point = os.path.join(base_dir, os.path.basename(device_node))

    try:
        os.makedirs(mount_point, exist_ok=True)
        mount_cmd = [
            "mount",
            device_node,
            mount_point,
        ]
        result = subprocess.run(mount_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(
                f"Failed to mount {device_node} at {mount_point}: {result.stderr.strip()}"
            )
            # Show recent kernel logs to aid diagnosis
            try:
                dmsg = subprocess.run(["dmesg"], capture_output=True, text=True)
                tail = "\n".join(dmsg.stdout.strip().splitlines()[-40:])
                print("Kernel messages (last 40 lines):\n" + tail)
            except Exception:
                pass
            return

        autorun_files = ["autorun.inf", "AUTORUN.INF", "Autorun.inf"]

        found_files = []
        for root, dirs, files in os.walk(mount_point):
            for file in files:
                if file in autorun_files:
                    found_files.append(os.path.join(root, file))

        if found_files:
            print("Autorun files found:")
            for file in found_files:
                print(f"  - {file}")
        else:
            print("No autorun files found.")

        # Here we can do OUR actual autorun handling logic, with safety checks.

    finally:
        subprocess.run(["umount", mount_point], check=False)
        try:
            os.rmdir(mount_point)
        except Exception:
            pass


if __name__ == "__main__":
    main()
