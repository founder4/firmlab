import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("patch", Path(__file__).with_name("patch-renode-security.py"))
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class ProjectPatch(unittest.TestCase):
    def test_only_target_dependency_is_updated(self):
        source = '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="9.0.1" /><PackageReference Include="Other" Version="1" /></ItemGroup></Project>'
        result = ET.fromstring(patch.patch_project(source))
        deps = {n.get("Include"): n.get("Version") for n in result.iter("PackageReference")}
        self.assertEqual(deps, {"Newtonsoft.Json": "13.0.4", "Other": "1"})

    def test_main_overrides_transitive_pkcs(self):
        result = ET.fromstring(patch.patch_project("<Project />", main=True))
        node = next(result.iter("PackageReference"))
        self.assertEqual((node.get("Include"), node.get("Version")), ("System.Security.Cryptography.Pkcs", "8.0.2"))


if __name__ == "__main__":
    unittest.main()
