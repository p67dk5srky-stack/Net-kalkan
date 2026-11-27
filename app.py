import os, re, socket, ipaddress, sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import requests
from flask import Flask, render_template, request, redirect, url_for, flash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "net_kalkan.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-before-deploying")

KEYWORDS = [
    "bahis", "casino", "kumar", "slot", "canlı bahis",
    "bahis bonusu", "deneme bonusu", "free spin"
]
HEADERS = {"User-Agent": "NetKalkan-Research/0.1 (public homepage review)"}

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL, domain TEXT NOT NULL, checked_at TEXT NOT NULL,
            status TEXT NOT NULL, matched TEXT NOT NULL, note TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS watchlist(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
            last_checked TEXT)""")

def validate_public_url(raw):
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Geçerli bir http/https adresi gir.")
    if p.username or p.password:
        raise ValueError("Kullanıcı adı/şifre içeren adresler kabul edilmiyor.")
    host = p.hostname.encode("idna").decode("ascii")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("Alan adı çözümlenemedi.")
    ips = {ipaddress.ip_address(x[4][0].split("%")[0]) for x in infos}
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Özel, yerel veya genel internete açık olmayan IP adresleri taranmaz.")
    return raw, host.lower()

def scan_one(raw):
    url, host = validate_public_url(raw)
    try:
        # Redirects are deliberately not followed. One public homepage request only.
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False,
                         stream=True, verify=True)
        chunks, total = [], 0
        for chunk in r.iter_content(8192):
            if not chunk: continue
            chunks.append(chunk); total += len(chunk)
            if total >= 300_000: break
        body = b"".join(chunks).decode(r.encoding or "utf-8", errors="ignore").lower()
        matched = sorted({k for k in KEYWORDS if k in body})
        status = "İnceleme gerekli" if matched else "Belirgin işaret bulunamadı"
        note = f"HTTP {r.status_code}; yönlendirme takip edilmedi; en fazla 300 KB ana sayfa incelendi."
        r.close()
    except requests.RequestException as e:
        matched, status, note = [], "Kontrol tamamlanamadı", f"Bağlantı hatası: {type(e).__name__}"
    checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db() as con:
        con.execute("INSERT INTO scans(url,domain,checked_at,status,matched,note) VALUES(?,?,?,?,?,?)",
                    (url, host, checked, status, ", ".join(matched), note))
    return status, matched, note

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        raw = request.form.get("url", "")
        try:
            if action == "add":
                url, _ = validate_public_url(raw)
                with db() as con:
                    con.execute("INSERT OR IGNORE INTO watchlist(url) VALUES(?)", (url,))
                flash("Adres izleme listesine eklendi. Otomatik tarama ayarı sunucuda ayrıca etkinleştirilmelidir.", "ok")
            else:
                status, matched, note = scan_one(raw)
                flash(f"{status}. Eşleşmeler: {', '.join(matched) if matched else 'yok'}. {note}", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("index"))
    with db() as con:
        scans = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 30").fetchall()
        watch = con.execute("SELECT * FROM watchlist ORDER BY id DESC").fetchall()
    return render_template("index.html", scans=scans, watch=watch)

@app.post("/watch/<int:item_id>/delete")
def delete_watch(item_id):
    with db() as con: con.execute("DELETE FROM watchlist WHERE id=?", (item_id,))
    flash("Adres izleme listesinden çıkarıldı.", "ok")
    return redirect(url_for("index"))

@app.post("/watch/scan")
def scan_watchlist():
    with db() as con:
        items = con.execute("SELECT * FROM watchlist WHERE enabled=1").fetchall()
    count = 0
    for item in items:
        try:
            scan_one(item["url"]); count += 1
            with db() as con:
                con.execute("UPDATE watchlist SET last_checked=? WHERE id=?",
                            (datetime.now(timezone.utc).isoformat(timespec="seconds"), item["id"]))
        except Exception:
            pass
    flash(f"İzleme listesindeki {count} adres kontrol edildi.", "ok")
    return redirect(url_for("index"))

init_db()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
