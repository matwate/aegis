from model import Autorun, AutorunFile
from pathlib import Path
import subprocess
from typing import List, Optional, Dict, Any
from safety import sha256_file


def _run_with_interpreter(interpreter: str | None, file_path: Path, args: list[str] | None) -> None:
    if not interpreter:
        raise ValueError("Interpreter is required to run a file.")
    cmd: List[str] = [interpreter, str(file_path)]
    if args:
        cmd.extend(args)
    subprocess.run(cmd, check=True)


def autorun(fileModel: AutorunFile, mountpoint: str, meta: Optional[Dict[str, Any]] = None) -> None:
    directive: Autorun = fileModel.autorun
    if directive.provides_file:
        file_path = Path(f"{mountpoint}/{directive.run.file}")
        if not file_path.is_file():
            raise FileNotFoundError(f"File {file_path} not found.")
        # Require signed file hash in metadata and enforce
        if not meta or not isinstance(meta, dict) or not meta.get("file_sha256"):
            raise ValueError("Missing signed file_sha256 in metadata; refusing to execute USB-provided file.")
        expected_hash = meta.get("file_sha256")
        actual_hash = sha256_file(str(file_path))
        if actual_hash != expected_hash:
            raise ValueError("USB file hash mismatch; refusing to execute.")
        _run_with_interpreter(directive.run.interpreter, file_path, directive.run.arguments)
    else:
        # Either the directive provides a command or the file is found in the host and not at the usb
        if directive.run.file:
            file_path = Path(f"/usr/local/autoruns/{directive.run.file}")
            if file_path.is_file():
                _run_with_interpreter(directive.run.interpreter, file_path, directive.run.arguments)
            else:
                raise FileNotFoundError(f"File {file_path} not found.")
        elif directive.run.command:
            subprocess.run(directive.run.command, shell=True, check=True)
