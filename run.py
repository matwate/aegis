from model import Autorun, AutorunFile
from pathlib import Path


def autorun(fileModel: AutorunFile, mountpoint: str) -> None:
    directive: Autorun = fileModel.autorun
    if directive.provides_file:
        file_path = Path(f"{mountpoint}/{directive.run.file}")
        if file_path.is_file():
            exec(f"{directive.run.interpreter} {file_path}")
        else:
            raise FileNotFoundError(f"File {file_path} not found.")
    else:
        # Either the directive provides a commmand or the file is found in the host and not at the usb
        if directive.run.file:
            file_path = Path(f"/usr/local/autoruns/{directive.run.file}")
            if file_path.is_file():
                exec(f"{directive.run.interpreter} {file_path}")
            else:
                raise FileNotFoundError(f"File {file_path} not found.")

        elif directive.run.command:
            exec(directive.run.command)
