from pydantic import BaseModel, model_validator
from pydantic_yaml import to_yaml_str, parse_yaml_file_as
from typing import Optional, Self


class RunConfig(BaseModel):
    file: Optional[str]
    interpreter: Optional[str]
    arguments: Optional[list[str]]
    command: Optional[str]

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        if self.command is None:
            if self.file is None:
                raise ValueError("Either 'command' or 'file' must be provided.")
            if self.interpreter is None:
                raise ValueError("'interpreter' must be provided when 'file' is used.")
            return self
        else:
            if self.file is not None:
                raise ValueError("'command' and 'file' cannot both be provided.")
            if self.interpreter is not None:
                raise ValueError("'command' and 'interpreter' cannot both be provided.")
            return self


class Autorun(BaseModel):
    """
    Model for an autorun directive
    """

    name: str
    description: Optional[str]
    run: RunConfig
    provides_file: bool

    @model_validator(mode="after")
    def validate_provides_file(self) -> Self:
        if self.provides_file and self.run.file is None:
            raise ValueError(
                "'provides_file' is True but no 'file' is specified in 'run'."
            )
        return self

    def get_autorun_path(self) -> Optional[str]:
        if self.run.file:
            if self.provides_file:
                return f"/usr/local/autoruns/{self.name}"
            else:
                # At runtime we append the file to the usb mountpoint
                return self.run.file
        else:
            return None


class AutorunFile(BaseModel):
    autorun: Autorun


if __name__ == "__main__":
    # Example usage that matches the YAML structure with an `autorun` root key
    example = AutorunFile(
        autorun=Autorun(
            name="example_autorun",
            description="An example autorun directive",
            run=RunConfig(
                file="script.sh",
                interpreter="/bin/bash",
                arguments=None,  # use null in YAML when unspecified
                command=None,    # use null in YAML when unspecified
            ),
            provides_file=True,
        )
    )
    print(to_yaml_str(example))

    model = parse_yaml_file_as(AutorunFile, "default.yaml")
    print(to_yaml_str(model))
