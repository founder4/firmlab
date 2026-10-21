"""Download only the pinned public build inputs; never reads firmware or app data."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request


def patch_mitmproxy(text):
    replacements = {
        '"msgpack>=1.0.0,<=1.1.2"': '"msgpack==1.2.3"',
        '"cryptography>=42.0,<=48.1"': '"cryptography==50.0.2"',
        '"tornado>=6.5.0,<=6.5.5"': '"tornado==6.5.9"',
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise ValueError(f"upstream dependency changed: {old}")
        text = text.replace(old, new)
    return text


def main():
    assets = json.loads(Path('/tmp/trixie-assets.json').read_text())
    for name, asset in assets.items():
        target = Path('/tmp') / (name if name.endswith('.deb') else name + '.tar.gz')
        with urllib.request.urlopen(asset['url'], timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != asset['sha256']:
            raise ValueError(f"checksum mismatch: {name}")
        target.write_bytes(data)
        if name == 'mitmproxy':
            with tarfile.open(target) as archive:
                archive.extractall('/tmp/mitmproxy-source', filter='data')
            project = next(Path('/tmp/mitmproxy-source').glob('*/pyproject.toml'))
            project.write_text(patch_mitmproxy(project.read_text()))


if __name__ == '__main__':
    main()
