import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('patch',Path(__file__).with_name('patch-mitmproxy-brotli.py'))
patch=importlib.util.module_from_spec(spec);spec.loader.exec_module(patch)

class PatchTests(unittest.TestCase):
    def test_narrow_constraint_and_explicit_local_version(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'mitmproxy').mkdir()
            (root/'pyproject.toml').write_text('dependencies=["Brotli>=1.0,<=1.2.0", "msgpack>=1.0.0,<=1.1.2", "cryptography>=42.0,<=48.1", "tornado>=6.5.0,<=6.5.5", "other"]')
            (root/'mitmproxy/version.py').write_text('VERSION = "12.2.3"\n')
            patch.patch(root)
            self.assertIn('"Brotli==1.2.1"',(root/'pyproject.toml').read_text())
            self.assertIn('"cryptography==50.0.2"',(root/'pyproject.toml').read_text())
            self.assertIn('12.2.3+homelab.20261103',(root/'mitmproxy/version.py').read_text())
    def test_unexpected_source_is_rejected(self):
        for source in ['', '"Brotli>=1.0,<=1.2.0"\n"Brotli>=1.0,<=1.2.0"']:
            with self.assertRaises(ValueError):patch.patched_project(source)

if __name__=='__main__':unittest.main()
