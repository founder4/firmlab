import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('assets', Path(__file__).with_name('fetch-trixie-assets.py'))
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class DependencyBounds(unittest.TestCase):
    def test_replaces_only_reviewed_bounds(self):
        result = assets.patch_mitmproxy('"msgpack>=1.0.0,<=1.1.2", "cryptography>=42.0,<=48.1", "tornado>=6.5.0,<=6.5.5", "other"')
        self.assertEqual(result, '"msgpack==1.2.3", "cryptography==50.0.2", "tornado==6.5.9", "other"')

    def test_refuses_changed_upstream(self):
        with self.assertRaises(ValueError):
            assets.patch_mitmproxy('"msgpack>=2"')


if __name__ == '__main__':
    unittest.main()
