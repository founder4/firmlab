"""Backport a narrow Brotli security constraint to the verified 12.2.3 source."""
from pathlib import Path
import sys


def patched_project(text):
    # Preserve the three source constraints already deployed on 22 October.
    replacements={
        '"Brotli>=1.0,<=1.2.0"':'"Brotli==1.2.1"',
        '"msgpack>=1.0.0,<=1.1.2"':'"msgpack==1.2.3"',
        '"cryptography>=42.0,<=48.1"':'"cryptography==50.0.2"',
        '"tornado>=6.5.0,<=6.5.5"':'"tornado==6.5.9"',
    }
    for old,new in replacements.items():
        if text.count(old)!=1:
            raise ValueError('Unexpected mitmproxy dependency declaration: '+old)
        text=text.replace(old,new)
    return text


def patch(root):
    project=root/'pyproject.toml';project.write_text(patched_project(project.read_text()))
    version=root/'mitmproxy/version.py';text=version.read_text()
    old='VERSION = "12.2.3"'
    if text.count(old)!=1:
        raise ValueError('Unexpected mitmproxy version source')
    version.write_text(text.replace(old,'VERSION = "12.2.3+homelab.20261103"'))


if __name__=='__main__':patch(Path(sys.argv[1]))
