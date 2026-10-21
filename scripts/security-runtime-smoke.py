"""Real tool checks in a disposable container with --network none and no data mount."""
import http.client
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=180, **kwargs)


def proxy_roundtrip(work):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'firmlab-synthetic-proxy-ok')

        def log_message(self, *_):
            pass

    plain = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    cert, key = work / 'origin.pem', work / 'origin.key'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    for server in (plain, tls):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    config = work / 'mitm'
    with (work / 'proxy.log').open('w') as log:
        process = subprocess.Popen(['mitmdump', '--listen-host', '127.0.0.1',
            '--listen-port', str(port), '--set', f'confdir={config}', '--ssl-insecure',
            '-w', str(work / 'flows')], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((work / 'proxy.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('proxy did not start')
            client = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            client.request('GET', f'http://127.0.0.1:{plain.server_port}/synthetic')
            assert client.getresponse().read() == b'firmlab-synthetic-proxy-ok'
            client.close()
            context = ssl.create_default_context(cafile=str(config / 'mitmproxy-ca-cert.pem'))
            client = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
            client.set_tunnel('localhost', tls.server_port)
            client.request('GET', '/synthetic-tls')
            assert client.getresponse().read() == b'firmlab-synthetic-proxy-ok'
            client.close()
        finally:
            process.terminate()
            process.wait(timeout=10)
            plain.shutdown()
            tls.shutdown()
    run('/opt/mitmproxy-venv/bin/python3', '-c',
        'from mitmproxy.io import FlowReader; import sys; '
        'flows=list(FlowReader(open(sys.argv[1],"rb")).stream()); '
        'assert len(flows)==2; assert all(f.response.status_code==200 for f in flows); '
        'import msgpack; assert msgpack.unpackb(msgpack.packb({"ok":True}))=={"ok":True}', str(work / 'flows'))
    print('PASS mitmproxy HTTP, HTTPS with trusted interception CA, saved flow roundtrip', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='firmlab-security-') as directory:
        work = Path(directory)
        project = work / 'ghidra-project'
        project.mkdir()
        output = work / 'decompiled.json'
        with (work / 'ghidra.log').open('w') as log:
            run('analyzeHeadless', str(project), 'synthetic', '-import', '/bin/true',
                '-scriptPath', '/app/apps/api/ghidra-scripts', '-postScript',
                'Decompile.java', str(output), '-deleteProject', stdout=log, stderr=log)
        data = json.loads(output.read_text())
        codes = [f['pseudocode'] for f in data['functions'] if f['pseudocode'].strip()]
        assert codes and any('return' in c for c in codes), data
        print(f'PASS Ghidra ARM64 native decompiler: {len(codes)} nonempty pseudocode functions', flush=True)
        run('/opt/angr-venv/bin/python3', '-c',
            'import angr; p=angr.Project("/bin/true",auto_load_libs=False); '
            's=p.factory.simgr(p.factory.entry_state()); s.step(); '
            'assert s.active and not s.errored; print("PASS angr symbolic execution step")')
        run('afl-showmap', '-Q', '-o', str(work / 'map'), '--', '/bin/cat',
            input=b'firmlab-synthetic\n', stdout=subprocess.DEVNULL)
        assert (work / 'map').stat().st_size > 0
        print('PASS AFL++ QEMU executes synthetic input and produces coverage', flush=True)
        proxy_roundtrip(work)


if __name__ == '__main__':
    main()
