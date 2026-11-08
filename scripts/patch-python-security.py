"""Apply narrow security constraints to existing runtime venvs using a temporary installer."""
from pathlib import Path
import json
import subprocess

INSTALLER='/tmp/security-installer/bin/python'
for directory in ('fw-py','angr-venv','fwhunt-venv','chipsec-venv','mitmproxy-venv'):
    python=Path('/opt')/directory/'bin/python3'
    installed=json.loads(subprocess.check_output([str(python),'-c',
        'import importlib.metadata as m,json;print(json.dumps({d.metadata["Name"].lower():d.version for d in m.distributions()}))'],text=True))
    wanted=[name+'=='+version for name,version in {'brotli':'1.2.1','pyasn1':'0.6.5'}.items() if name in installed]
    if wanted:
        subprocess.run([INSTALLER,'-m','pip','--python',str(python),'install','--no-cache-dir','--no-deps',*wanted],check=True)
    subprocess.run([INSTALLER,'-m','pip','--python',str(python),'check'],check=True)
    freeze=subprocess.check_output([INSTALLER,'-m','pip','--python',str(python),'freeze'],text=True)
    (python.parent.parent/'firmlab-lock.txt').write_text(freeze)
