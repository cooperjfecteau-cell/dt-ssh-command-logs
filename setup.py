from pathlib import Path

from setuptools import find_packages, setup


def find_version() -> str:
    """Keep the wheel version in step with extension.yaml, which is the source of truth."""
    version = "0.0.1"
    extension_yaml_path = Path(__file__).parent / "extension" / "extension.yaml"
    try:
        with open(extension_yaml_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("version"):
                    version = line.split(" ")[-1].strip('"').strip()
                    break
    except Exception:
        pass
    return version


setup(
    name="ssh_command_logs",
    version=find_version(),
    description="Run a command on a Linux host over SSH and ingest the terminal output as Dynatrace logs",
    author="Cooper Fecteau",
    packages=find_packages(exclude=["tests", "tests.*", "tools", "tools.*"]),
    python_requires=">=3.10",
    include_package_data=True,
    install_requires=["dt-extensions-sdk", "paramiko>=3.4"],
    extras_require={"dev": ["dt-extensions-sdk[cli]", "pytest"]},
)
