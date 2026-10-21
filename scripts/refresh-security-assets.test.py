import importlib.util
from pathlib import Path
import unittest
import tarfile

spec = importlib.util.spec_from_file_location(
    "refresh", Path(__file__).with_name("refresh-security-assets.py")
)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class ArchivePaths(unittest.TestCase):
    def test_relative_paths(self):
        self.assertTrue(refresh.safe_name("ghidra/support/analyzeHeadless"))

    def test_absolute_and_parent_paths(self):
        for name in ("/etc/passwd", "../escape", "ghidra/../../escape"):
            self.assertFalse(refresh.safe_name(name))

    def test_tar_links_cannot_traverse(self):
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc"
        with self.assertRaises(refresh.tarfile.LinkOutsideDestinationError):
            refresh.tarfile.data_filter(link, "/tmp/security-test-root")

    def test_tar_devices_are_refused(self):
        device = tarfile.TarInfo("device")
        device.type = tarfile.CHRTYPE
        with self.assertRaises(ValueError):
            refresh.validate_tar([device])


if __name__ == "__main__":
    unittest.main()
