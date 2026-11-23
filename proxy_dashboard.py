"""
Middleman Proxy Relay Dashboard  -  pure Python (no 3proxy.exe needed).

Run:   python proxy_dashboard.py
Open:  http://127.0.0.1:8088

Standard library only. Needs curl.exe for the IP checks (ships with Windows 10/11).
The dashboard and the proxies listen on 127.0.0.1 only; never expose them to a network.
"""
import base64, hmac, json, os, re, select, socket, socketserver, struct, subprocess, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PANEL_PORT = 8088
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_settings.json")
IP_URL = "https://api.ipify.org"

DEFAULTS = {
    "user": "testuser", "password": "testpass", "auth_strong": True,
    "socks_port": 1080, "http_port": 3128,
    "relay_enabled": False, "relay_type": "socks5",
    "relay_host": "", "relay_port": 1080, "relay_user": "", "relay_pass": "",
}

TOKEN_RE = re.compile(r"^[A-Za-z0-9._@~\-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


# ----------------------------------------------------------------- settings
def clean(s, regex, name):
    s = str(s).strip()
    if not regex.match(s):
        raise ValueError(f"Invalid {name}: only letters, digits and . _ @ ~ - allowed")
    return s


def port(v, name):
    v = int(v)
    if not 1 <= v <= 65535:
        raise ValueError(f"{name} must be 1-65535")
    return v


def validate(d):
    s = dict(DEFAULTS)
    s.update(d or {})
    rt = "socks5" if s["relay_type"] == "socks5" else "http"
    out = {
        "user": clean(s["user"], TOKEN_RE, "username"),
        "password": clean(s["password"], TOKEN_RE, "password"),
        "auth_strong": bool(s["auth_strong"]),
        "socks_port": port(s["socks_port"], "SOCKS port"),
        "http_port": port(s["http_port"], "HTTP port"),
        "relay_enabled": bool(s["relay_enabled"]),
        "relay_type": rt,
        "relay_host": "", "relay_port": 1080, "relay_user": "", "relay_pass": "",
    }
    if out["relay_enabled"]:
        out["relay_host"] = clean(s["relay_host"], HOST_RE, "relay host")
        out["relay_port"] = port(s["relay_port"], "relay port")
        if str(s["relay_user"]).strip():
            out["relay_user"] = clean(s["relay_user"], TOKEN_RE, "relay username")
            out["relay_pass"] = clean(s["relay_pass"], TOKEN_RE, "relay password")
    if out["socks_port"] == out["http_port"]:
        raise ValueError("SOCKS and HTTP ports must differ")
    return out


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return validate(json.load(f))
    except Exception:
        return dict(DEFAULTS)


# ------------------------------------------------------------ proxy engine
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise ConnectionError("connection closed")
        buf += d
    return buf


def read_head(sock):
    """Read up to the blank line ending an HTTP head. Returns (head, leftover)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > 65536:
            raise ValueError("header too large")
        d = sock.recv(4096)
        if not d:
            raise ConnectionError("connection closed")
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def socks5_connect(sock, s, host, port_):
    user = s["relay_user"]
    sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    _, method = recv_exact(sock, 2)
    if method == 2 and user:
        u, p = user.encode(), s["relay_pass"].encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if recv_exact(sock, 2)[1] != 0:
            raise OSError("relay login failed")
    elif method != 0:
        raise OSError("relay rejected login method")
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack("!H", port_))
    rep = recv_exact(sock, 4)
    if rep[1] != 0:
        raise OSError(f"relay refused connection (code {rep[1]})")
    if rep[3] == 1:
        recv_exact(sock, 6)
    elif rep[3] == 4:
        recv_exact(sock, 18)
    else:
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)


def http_connect(sock, s, host, port_):
    req = f"CONNECT {host}:{port_} HTTP/1.1\r\nHost: {host}:{port_}\r\n"
    if s["relay_user"]:
        tok = base64.b64encode(f"{s['relay_user']}:{s['relay_pass']}".encode()).decode()
        req += f"Proxy-Authorization: Basic {tok}\r\n"
    sock.sendall((req + "\r\n").encode())
    head, _ = read_head(sock)
    status = head.split(b"\r\n", 1)[0]
    parts = status.split(b" ")
    if len(parts) < 2 or parts[1] != b"200":
        raise OSError("relay refused: " + status.decode("latin-1", "replace"))


def open_upstream(s, host, port_):
    """Connect to the target directly, or through the configured relay (parent) hop."""
    if not s["relay_enabled"]:
        return socket.create_connection((host, port_), timeout=10)
    sock = socket.create_connection((s["relay_host"], s["relay_port"]), timeout=10)
    try:
        if s["relay_type"] == "socks5":
            socks5_connect(sock, s, host, port_)
        else:
            http_connect(sock, s, host, port_)
    except Exception:
        sock.close()
        raise
    return sock


def pipe(a, b):
    a.settimeout(None)
    b.settimeout(None)
    try:
        while True:
            r, _, x = select.select([a, b], [], [a, b], 120)
            if x or not r:
                break
            for src in r:
                d = src.recv(65536)
                if not d:
                    return
                (b if src is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for sk in (a, b):
            try:
                sk.close()
            except OSError:
                pass


def creds_ok(s, user_b, pass_b):
    if not s["auth_strong"]:
        return True
    ok1 = hmac.compare_digest(user_b, s["user"].encode())
    ok2 = hmac.compare_digest(pass_b, s["password"].encode())
    return ok1 and ok2


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        c, s = self.request, self.server.s
        try:
            c.settimeout(15)
            ver, n = recv_exact(c, 2)
            if ver != 5:
                return
            methods = recv_exact(c, n)
            if s["auth_strong"]:
                if 2 not in methods:
                    c.sendall(b"\x05\xff")
                    return
                c.sendall(b"\x05\x02")
                recv_exact(c, 1)
                u = recv_exact(c, recv_exact(c, 1)[0])
                p = recv_exact(c, recv_exact(c, 1)[0])
                ok = creds_ok(s, u, p)
                c.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
                if not ok:
                    return
            else:
                c.sendall(b"\x05\x00")
            _, cmd, _, atyp = recv_exact(c, 4)
            if atyp == 1:
                host = socket.inet_ntoa(recv_exact(c, 4))
            elif atyp == 3:
                host = recv_exact(c, recv_exact(c, 1)[0]).decode("idna")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(c, 16))
            else:
                c.sendall(b"\x05\x08\x00\x01" + bytes(6))
                return
            port_ = struct.unpack("!H", recv_exact(c, 2))[0]
            if cmd != 1:
                c.sendall(b"\x05\x07\x00\x01" + bytes(6))
                return
            try:
                up = open_upstream(s, host, port_)
            except Exception:
                c.sendall(b"\x05\x05\x00\x01" + bytes(6))
                return
            c.sendall(b"\x05\x00\x00\x01" + bytes(6))
            pipe(c, up)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        c, s = self.request, self.server.s
        up = None
        try:
            c.settimeout(15)
            head, rest = read_head(c)
            lines = head.decode("latin-1").split("\r\n")
            method, target, ver = lines[0].split(" ", 2)
            headers = lines[1:]
            if s["auth_strong"]:
                cred = b""
                for h in headers:
                    if h.lower().startswith("proxy-authorization:"):
                        v = h.split(":", 1)[1].strip()
                        if v.lower().startswith("basic "):
                            try:
                                cred = base64.b64decode(v[6:])
                            except Exception:
                                pass
                u, _, p = cred.partition(b":")
                if not creds_ok(s, u, p):
                    c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                              b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                              b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    return
            if method.upper() == "CONNECT":
                host, _, p = target.rpartition(":")
                up = open_upstream(s, host.strip("[]"), int(p))
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                m = re.match(r"^http://([^/:]+)(?::(\d+))?(/.*)?$", target, re.I)
                if not m:
                    c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                host, p_, path = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
                up = open_upstream(s, host, p_)
                keep = [h for h in headers if h and not h.lower().startswith(
                    ("proxy-authorization:", "proxy-connection:", "connection:"))]
                req = f"{method} {path} {ver}\r\n" + "\r\n".join(keep) + "\r\nConnection: close\r\n\r\n"
                up.sendall(req.encode("latin-1") + rest)
            pipe(c, up)
        except Exception:
            if up is None:
                try:
                    c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
        finally:
            try:
                c.close()
            except OSError:
                pass


class TServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = os.name != "nt"   # on Windows SO_REUSEADDR would allow port hijacking
    daemon_threads = True


class Engine:
    def __init__(self):
        self.servers = []
        self.lock = threading.Lock()

    def running(self):
        return bool(self.servers)

    def start(self, s):
        with self.lock:
            if self.servers:
                return "Proxy is already running"
            made, cur = [], None
            try:
                for handler, p in ((SocksHandler, s["socks_port"]), (HttpHandler, s["http_port"])):
                    cur = p
                    srv = TServer(("127.0.0.1", p), handler)
                    srv.s = s
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    made.append(srv)
            except OSError as e:
                for m in made:
                    m.shutdown()
                    m.server_close()
                raise ValueError(f"Cannot listen on port {cur}: {e}")
            self.servers = made
            return f"Proxy started (SOCKS5 :{s['socks_port']}, HTTP :{s['http_port']})"

    def stop(self):
        with self.lock:
            if not self.servers:
                return "Proxy was not running"
            for srv in self.servers:
                srv.shutdown()
                srv.server_close()
            self.servers = []
            return "Proxy stopped"


ENGINE = Engine()


# ---------------------------------------------------------------- dashboard
def curl_ip(extra):
    try:
        r = subprocess.run(["curl.exe", "-s", "--max-time", "8", *extra, IP_URL],
                           capture_output=True, text=True, timeout=12)
        ip = r.stdout.strip()
        if r.returncode == 0 and re.match(r"^[0-9a-fA-F:.]{3,45}$", ip):
            return {"ok": True, "ip": ip}
        return {"ok": False, "error": f"curl exit {r.returncode} (proxy not running, wrong login, or relay failing)"}
    except FileNotFoundError:
        return {"ok": False, "error": "curl.exe not found"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_ips():
    s = load_settings()
    cred = f"{s['user']}:{s['password']}"
    jobs = {
        "direct": [],
        "socks": ["--socks5-hostname", f"127.0.0.1:{s['socks_port']}", "--proxy-user", cred],
        "http": ["--proxy", f"http://127.0.0.1:{s['http_port']}", "--proxy-user", cred],
    }
    res = {}

    def run(k):
        res[k] = curl_ip(jobs[k])
    ts = [threading.Thread(target=run, args=(k,)) for k in jobs]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return res


def status():
    s = ENGINE.servers[0].s if ENGINE.running() else load_settings()
    run = ENGINE.running()
    return {
        "process": run,
        "socks": {"port": s["socks_port"], "listening": run},
        "http": {"port": s["http_port"], "listening": run},
        "relay": s["relay_enabled"],
        "relay_desc": f"{s['relay_type']}://{s['relay_host']}:{s['relay_port']}" if s["relay_enabled"] else "",
    }


def ps_snippets(s):
    sp, hp = s["socks_port"], s["http_port"]
    cred = f"{s['user']}:{s['password']}"
    return {
        "status": f"Get-NetTCPConnection -LocalPort {sp},{hp} -State Listen",
        "test": (f"curl.exe {IP_URL}\n"
                 f"curl.exe --socks5h 127.0.0.1:{sp} --proxy-user {cred} {IP_URL}\n"
                 f"curl.exe --proxy http://127.0.0.1:{hp} --proxy-user {cred} {IP_URL}"),
    }


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PANEL_PORT}", f"localhost:{PANEL_PORT}")

    def do_GET(self):
        if not self._host_ok():
            return self._json({"error": "bad host"}, 403)
        if self.path == "/":
            return self._send(200, PAGE, "text/html")
        if self.path == "/api/settings":
            s = load_settings()
            return self._json({"settings": s, "ps": ps_snippets(s)})
        if self.path == "/api/status":
            return self._json(status())
        if self.path == "/api/ips":
            return self._json(check_ips())
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Panel") != "1":
            return self._json({"error": "forbidden"}, 403)
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
            if self.path == "/api/preview":
                return self._json({"ps": ps_snippets(validate(data))})
            if self.path == "/api/save":
                s = validate(data)
                with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                    json.dump(s, f, indent=2)
                note = " Restart the proxy to apply." if ENGINE.running() else " Click Start to run it."
                return self._json({"message": "Settings saved." + note})
            if self.path == "/api/start":
                return self._json({"message": ENGINE.start(load_settings())})
            if self.path == "/api/stop":
                return self._json({"message": ENGINE.stop()})
            if self.path == "/api/restart":
                ENGINE.stop()
                return self._json({"message": ENGINE.start(load_settings())})
            self._json({"error": "not found"}, 404)
        except (ValueError, TypeError, KeyError) as e:
            self._json({"error": str(e)}, 400)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Middleman Proxy Relay Dashboard</title>
<style>
:root{--bg:#0b0f14;--panel:#121923;--line:#1f2a38;--tx:#d6e2f0;--dim:#7d8da1;--ok:#3ddc97;--bad:#ff5c6c;--warn:#ffb454;--acc:#4cc2ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,Segoe UI,sans-serif}
.mono,code,pre,input,textarea,select{font-family:Consolas,"Cascadia Mono",monospace}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:18px;margin:0;letter-spacing:.5px}h2{font-size:13px;text-transform:uppercase;letter-spacing:1.5px;color:var(--dim);margin:0 0 12px}
main{max-width:1150px;margin:0 auto;padding:20px;display:grid;gap:18px}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.big{font-size:22px;margin:6px 0;word-break:break-all}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;border:1px solid}
.ok{color:var(--ok);border-color:var(--ok)}.bad{color:var(--bad);border-color:var(--bad)}.warn{color:var(--warn);border-color:var(--warn)}.dim{color:var(--dim);border-color:var(--line)}
button{background:#1b2a3d;color:var(--tx);border:1px solid #2c4560;border-radius:6px;padding:7px 13px;cursor:pointer}
button:hover{border-color:var(--acc)}button.p{background:var(--acc);color:#001018;border-color:var(--acc);font-weight:600}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
form{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
label{display:grid;gap:4px;color:var(--dim);font-size:12px}
input,select{background:#0b1119;color:var(--tx);border:1px solid var(--line);border-radius:6px;padding:7px}
input[type=checkbox]{width:auto}
pre{background:#080c11;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;margin:6px 0 10px;white-space:pre-wrap;word-break:break-all}
.note{color:var(--dim);font-size:13px}#msg{min-height:22px}
</style></head><body>
<header><h1>▣ Middleman Proxy Relay Dashboard</h1><span id="proc" class="badge dim">…</span>
<div class="row" style="margin-left:auto"><button onclick="act('start')">Start</button><button onclick="act('stop')">Stop</button><button onclick="act('restart')">Restart</button></div></header>
<main>
<div id="msg" class="mono"></div>
<section><h2>Middleman Status</h2>
<div class="grid">
<div class="card"><div class="note">Direct IP</div><div id="ip_direct" class="big mono">—</div><span id="b_direct" class="badge dim">unchecked</span></div>
<div class="card"><div class="note">SOCKS5 <span id="sp" class="mono"></span></div><div id="ip_socks" class="big mono">—</div><span id="b_socks" class="badge dim">unchecked</span> <span id="l_socks" class="badge dim"></span></div>
<div class="card"><div class="note">HTTP proxy <span id="hp" class="mono"></span></div><div id="ip_http" class="big mono">—</div><span id="b_http" class="badge dim">unchecked</span> <span id="l_http" class="badge dim"></span></div>
<div class="card"><div class="note">Relay / chaining</div><div id="relay" class="big mono">—</div><span id="b_relay" class="badge dim">—</span></div>
</div>
<div class="row" style="margin-top:12px"><button class="p" onclick="check()">Check IPs now</button><span id="cmp" class="note"></span></div>
<p class="note">A local proxy only affects apps configured to use it (or tools like curl). A VPN adapter changes OS-level routing. If a VPN is active, the "direct" IP is already the VPN's exit, and a relay hop changes only what the proxy ports use. With no relay, all three IPs will match.</p>
</section>

<section class="card"><h2>Proxy &amp; Relay Settings</h2>
<form id="f" oninput="preview()">
<label>Username<input name="user"></label><label>Password<input name="password"></label>
<label>SOCKS5 port<input name="socks_port" type="number"></label><label>HTTP port<input name="http_port" type="number"></label>
<label><span>Require login</span><input name="auth_strong" type="checkbox"></label>
<label><span>Enable upstream relay (parent)</span><input name="relay_enabled" type="checkbox"></label>
<label>Relay protocol<select name="relay_type"><option value="socks5">socks5</option><option value="http">http (CONNECT)</option></select></label>
<label>Relay host<input name="relay_host"></label><label>Relay port<input name="relay_port" type="number"></label>
<label>Relay username (optional)<input name="relay_user"></label><label>Relay password<input name="relay_pass"></label>
</form>
<div class="row" style="margin-top:14px"><button class="p" onclick="save()">Save settings</button><span class="note">Save, then Start (or Restart if already running).</span></div>
</section>

<section class="card"><h2>PowerShell Diagnostics</h2>
<div id="ps"></div></section>
</main>
<script>
const $=id=>document.getElementById(id);let T;
async function api(p,body){const o=body===undefined?{}:{method:'POST',headers:{'X-Panel':'1','Content-Type':'application/json'},body:JSON.stringify(body)};
 const r=await fetch(p,o);const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function msg(t,bad){const m=$('msg');m.textContent=t;m.style.color=bad?'var(--bad)':'var(--ok)'}
function badge(el,t,c){el.textContent=t;el.className='badge '+c}
function form(){const o={};for(const e of $('f').elements){if(!e.name)continue;o[e.name]=e.type==='checkbox'?e.checked:e.value}return o}
function fill(s){for(const e of $('f').elements){if(!e.name)continue;if(e.type==='checkbox')e.checked=!!s[e.name];else e.value=s[e.name]}}
function show(d){const P=$('ps');P.textContent='';
 const t={status:'Check listeners',test:'Test IPs with curl'};
 for(const k in t){const h=document.createElement('div');h.className='note';h.textContent=t[k];const p=document.createElement('pre');p.className='mono';p.id='ps_'+k;p.textContent=d.ps[k];
  const b=document.createElement('button');b.textContent='Copy';b.onclick=()=>copy('ps_'+k);P.append(h,p,b)}}
function preview(){clearTimeout(T);T=setTimeout(async()=>{try{show(await api('/api/preview',form()));msg('')}catch(e){msg(e.message,1)}},250)}
async function save(){try{msg((await api('/api/save',form())).message)}catch(e){msg(e.message,1)}}
async function act(a){try{msg((await api('/api/'+a,{})).message);setTimeout(refresh,500)}catch(e){msg(e.message,1)}}
function copy(id){navigator.clipboard.writeText($(id).textContent);msg('Copied')}
async function refresh(){try{const s=await api('/api/status');
 badge($('proc'),s.process?'proxy running':'proxy stopped',s.process?'ok':'bad');
 $('sp').textContent=':'+s.socks.port;$('hp').textContent=':'+s.http.port;
 badge($('l_socks'),s.socks.listening?'Listening':'Stopped',s.socks.listening?'ok':'bad');
 badge($('l_http'),s.http.listening?'Listening':'Stopped',s.http.listening?'ok':'bad');
 $('relay').textContent=s.relay?s.relay_desc:'Direct exit';badge($('b_relay'),s.relay?'Relay Active':'Direct Exit',s.relay?'warn':'dim')}catch(e){msg(e.message,1)}}
async function check(){['direct','socks','http'].forEach(k=>{$('ip_'+k).textContent='…';badge($('b_'+k),'checking','dim')});
 try{const r=await api('/api/ips');for(const k of ['direct','socks','http']){const v=r[k];
  $('ip_'+k).textContent=v.ok?v.ip:'—';badge($('b_'+k),v.ok?'OK':'Error',v.ok?'ok':'bad');if(!v.ok)$('ip_'+k).title=v.error}
  const d=r.direct,s=r.socks,h=r.http;
  $('cmp').textContent=!d.ok?'Direct check failed.':[s.ok&&(s.ip!==d.ip?'SOCKS exit differs from direct':'SOCKS exit equals direct'),h.ok&&(h.ip!==d.ip?'HTTP exit differs from direct':'HTTP exit equals direct')].filter(Boolean).join(' · ')||'Proxy ports unreachable (click Start first; check credentials)';
 }catch(e){msg(e.message,1)}}
(async()=>{try{const d=await api('/api/settings');fill(d.settings);show(d)}catch(e){msg(e.message,1)}refresh();setInterval(refresh,5000)})();
</script></body></html>"""

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PANEL_PORT), H)
    print(f"Dashboard: http://127.0.0.1:{PANEL_PORT}   (Ctrl+C to quit)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        ENGINE.stop()