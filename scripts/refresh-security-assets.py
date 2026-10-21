"""Install official, digest-verified ARM64 tool releases into a candidate image.

Runs only during Docker builds; firmware and production state are never inputs.
"""
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

if not hasattr(tarfile, "data_filter"):
    from backports import tarfile


def safe_name(name):
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def validate_tar(members):
    # Additional path/type checks; data_filter handles symlink traversal against
    # the actual extraction directory, including legitimate internal ../ links.
    for member in members:
        if not safe_name(member.name):
            raise ValueError("unsafe archive path")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError("unsupported archive entry")


def install(asset):
    with urllib.request.urlopen(asset["url"], timeout=300) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != asset["sha256"]:
        raise ValueError("digest mismatch: " + asset["url"])
    target = Path(asset["target"])
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory)
        if asset["kind"] == "binary":
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                member = next(m for m in archive if m.name == target.name and m.isfile())
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755)
            return
        if asset["kind"] == "tar":
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                validate_tar(archive.getmembers())
                archive.extractall(stage, filter="data")
        elif asset["kind"] == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if not all(safe_name(n) for n in archive.namelist()):
                    raise ValueError("unsafe archive path")
                archive.extractall(stage)
                for entry in archive.infolist():
                    mode = entry.external_attr >> 16
                    if mode & 0o111:
                        (stage / entry.filename).chmod(mode & 0o777)
        else:
            raise ValueError("unknown archive kind")
        entries = list(stage.iterdir())
        source = entries[0] if len(entries) == 1 and entries[0].is_dir() else stage
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, symlinks=True)


if __name__ == "__main__":
    for item in json.loads(Path(sys.argv[1]).read_text()):
        print("Installing", item["release"], flush=True)
        install(item)
