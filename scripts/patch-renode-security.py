"""Patch the verified Renode source package before a clean, self-contained build."""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def patch_project(text, main=False):
    root = ET.fromstring(text)
    for node in root.iter():
        if node.tag.endswith("PackageReference") and node.get("Include") == "Newtonsoft.Json":
            node.set("Version", "13.0.4")
    if main:
        group = ET.SubElement(root, "ItemGroup")
        ET.SubElement(group, "PackageReference", Include="System.Security.Cryptography.Pkcs", Version="8.0.2")
    return ET.tostring(root, encoding="unicode")


def patch_source(root):
    for project in root.rglob("*.csproj"):
        text = project.read_text(encoding="utf-8-sig")
        main = project == root / "src/Renode/Renode.csproj"
        if "Newtonsoft.Json" in text or main:
            project.write_text(patch_project(text, main))
    # The release source includes an offline cache. Permit official NuGet for the
    # patched framework/dependencies instead of silently reusing the old runtime.
    (root / "NuGet.Config").write_text(
        '<configuration><packageSources><clear />'
        '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
        '</packageSources></configuration>'
    )


if __name__ == "__main__":
    patch_source(Path(sys.argv[1]))
