import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
import brotli

exe = pathlib.Path(sys.argv[1]).resolve()
label = sys.argv[2]
subprocess.run([str(exe), 'version'], check=True)
modules = subprocess.check_output([str(exe), 'list-modules'], text=True)
assert 'http.encoders.br' in modules
php = subprocess.check_output([str(exe), 'php-cli', '-r', 'echo PHP_VERSION;'], text=True)
assert '8.5.12' in php, php
web = pathlib.Path('web').resolve()
web.mkdir(exist_ok=True)
fragment = 'FrankenPHP Winlibs Brotli compatibility. '
payload = (fragment * 2048).encode()
(web / 'index.php').write_text("<?php header('Content-Type: text/plain'); echo str_repeat('" + fragment + "', 2048);")
config = pathlib.Path('Caddyfile.compat').resolve()
config.write_text('''{
    admin off
    auto_https off
}
http://127.0.0.1:9080 {
    root * "''' + web.as_posix() + '''"
    encode br
    php_server
}
''')
log = pathlib.Path(label + '.log').open('w')
process = subprocess.Popen([str(exe), 'run', '--config', str(config), '--adapter', 'caddyfile'], stdout=log, stderr=log)
def request():
    req = urllib.request.Request('http://127.0.0.1:9080/', headers={'Accept-Encoding': 'br'})
    with urllib.request.urlopen(req, timeout=15) as response:
        assert response.status == 200
        assert response.headers['Content-Encoding'] == 'br', dict(response.headers)
        compressed = response.read()
        assert brotli.decompress(compressed) == payload
        return len(compressed)
try:
    for attempt in range(60):
        if process.poll() is not None:
            raise RuntimeError('Server exited early: ' + pathlib.Path(label + '.log').read_text())
        try:
            size = request()
            break
        except urllib.error.URLError:
            time.sleep(0.5)
    else:
        raise RuntimeError('Server did not start')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        sizes = list(pool.map(lambda _: request(), range(64)))
    report = {'executable': exe.name, 'sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
              'php': php, 'requests': len(sizes) + 1, 'payload_bytes': len(payload),
              'compressed_bytes': sorted(set(sizes)), 'content_encoding': 'br', 'result': 'PASS'}
    pathlib.Path(label + '-evidence.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
finally:
    process.terminate()
    process.wait(timeout=30)
    log.close()
