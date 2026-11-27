
import os
import re
import time
import socket
import sqlite3
import threading
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "net-kalkan-change-this-secret")

DATABASE = os.environ.get("DATABASE_PATH", "net_kalkan.db")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL_HOURS", "6")) * 3600

HEADERS = {
    "User-Agent": "NET-KALKAN/2.0 Website Safety Scanner",
    "Accept": "text/html,application/xhtml+xml,text/plain"
}

KEYWORDS = [
    "kaçak bahis", "yasa dışı bahis", "yasadışı bahis",
    "bahis oyna", "canlı bahis", "casino", "casinos",
    "slot oyunları", "deneme bonusu", "hoşgeldin bonusu",
    "hoş geldin bonusu", "yatırım bonusu", "bedava bahis",
    "bahis bonusu", "free spin", "free spins", "betting",
    "sports betting", "online casino", "casino bonus",
    "live casino", "bet bonus", "deposit bonus",
    "bahis sitesi", "canlı casino", "rulet", "blackjack",
    "poker", "jackpot", "oranlar", "kupon yap",
    "papara ile yatırım", "kripto ile yatırım"
]

MAX_PAGES = 30
MAX_PAGE_BYTES = 250_000
MAX_TOTAL_BYTES = 3_000_000
REQUEST_TIMEOUT = 8
MAX_REDIRECTS = 3

scan_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    con = sqlite3.connect(DATABASE, timeout=20)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                matched TEXT,
                note TEXT,
                rating INTEGER DEFAULT 1,
                reason TEXT DEFAULT ''
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                enabled INTEGER DEFAULT 1,
                last_checked TEXT DEFAULT ''
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                name TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Eski veritabanlarında eksik olabilecek sütunları ekle.
        scan_columns = {
            row["name"] for row in
            con.execute("PRAGMA table_info(scans)").fetchall()
        }

        if "rating" not in scan_columns:
            con.execute("ALTER TABLE scans ADD COLUMN rating INTEGER DEFAULT 1")

        if "reason" not in scan_columns:
            con.execute("ALTER TABLE scans ADD COLUMN reason TEXT DEFAULT ''")

        watch_columns = {
            row["name"] for row in
            con.execute("PRAGMA table_info(watchlist)").fetchall()
        }

        if "enabled" not in watch_columns:
            con.execute("ALTER TABLE watchlist ADD COLUMN enabled INTEGER DEFAULT 1")

        if "last_checked" not in watch_columns:
            con.execute("ALTER TABLE watchlist ADD COLUMN last_checked TEXT DEFAULT ''")

        con.execute("""
            INSERT OR IGNORE INTO settings(name, value)
            VALUES('counter_reset_at', '1970-01-01T00:00:00+00:00')
        """)

        con.execute("""
            INSERT OR IGNORE INTO settings(name, value)
            VALUES('last_auto_scan', '')
        """)


def normalize_host(host):
    if not host:
        raise ValueError("Geçerli bir internet adresi gir.")

    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        raise ValueError("İnternet adresi geçersiz.")


def validate_public_url(raw):
    raw = (raw or "").strip()

    if not raw:
        raise ValueError("Lütfen bir internet adresi gir.")

    if len(raw) > 2048:
        raise ValueError("Adres çok uzun.")

    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Yalnızca HTTP ve HTTPS adresleri kontrol edilebilir.")

    if not parsed.hostname:
        raise ValueError("Geçerli bir internet adresi gir.")

    if parsed.username or parsed.password:
        raise ValueError("Kullanıcı bilgisi içeren adresler kabul edilmez.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Adresin bağlantı noktası geçersiz.")

    if port not in (None, 80, 443):
        raise ValueError("Yalnızca standart web bağlantı noktaları kullanılabilir.")

    host = normalize_host(parsed.hostname)

    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Yerel ağ adresleri kontrol edilemez.")

    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Özel veya yerel IP adresleri kontrol edilemez.")
    except ValueError as exc:
        if "kontrol edilemez" in str(exc):
            raise

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("İnternet adresinin DNS kaydı bulunamadı.")

    if not addresses:
        raise ValueError("İnternet adresi çözümlenemedi.")

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ValueError("Özel veya yerel ağlara yönlenen adresler kabul edilmez.")

    clean = parsed._replace(
        netloc=host,
        fragment=""
    ).geturl()

    return clean, host


def fetch_page(url, expected_host):
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        current, current_host = validate_public_url(current)

        if current_host != expected_host:
            raise ValueError("Farklı alan adına yönlendirme engellendi.")

        response = requests.get(
            current,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True
        )

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            response.close()

            if not location:
                raise ValueError("Yönlendirme adresi bulunamadı.")

            current = urljoin(current, location)
            continue

        return response

    raise ValueError("Çok fazla yönlendirme yapıldı.")


def calculate_rating(matched):
    count = len(matched)

    if count == 0:
        return 1, "Belirgin şüpheli kelime eşleşmesi bulunamadı."

    if count <= 2:
        return 2, "Az sayıda şüpheli ifade bulundu. İnsan kontrolü önerilir."

    if count <= 5:
        return 3, "Birden fazla şüpheli ifade bulundu. Ayrıntılı inceleme önerilir."

    if count <= 9:
        return 4, "Çok sayıda şüpheli ifade bulundu. Öncelikli inceleme önerilir."

    return 5, "Yoğun şüpheli ifade eşleşmesi bulundu. Öncelikli inceleme önerilir."


def save_failed_scan(url, host, message):
    with db() as con:
        con.execute("""
            INSERT INTO scans
            (url, domain, checked_at, status, matched, note, rating, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url, host, now(), "Tarama başarısız",
            "", message, 0, message
        ))


def scan_one(raw):
    start_url, host = validate_public_url(raw)

    queue = [start_url]
    seen = set()
    matched_all = set()

    pages = 0
    total_bytes = 0
    http_code = "Bilinmiyor"
    errors = []

    while queue and pages < MAX_PAGES and total_bytes < MAX_TOTAL_BYTES:
        current = queue.pop(0)

        try:
            current, current_host = validate_public_url(current)

            if current_host != host or current in seen:
                continue

            seen.add(current)
            response = fetch_page(current, host)

            try:
                if pages == 0:
                    http_code = str(response.status_code)

                if response.status_code >= 400:
                    errors.append(f"HTTP {response.status_code}")
                    continue

                content_type = response.headers.get("Content-Type", "").lower()

                if not any(x in content_type for x in (
                    "text/html", "text/plain", "application/xhtml"
                )):
                    continue

                chunks = []
                page_bytes = 0

                for chunk in response.iter_content(8192):
                    if not chunk:
                        continue

                    remaining = min(
                        MAX_PAGE_BYTES - page_bytes,
                        MAX_TOTAL_BYTES - total_bytes
                    )

                    if remaining <= 0:
                        break

                    chunk = chunk[:remaining]
                    chunks.append(chunk)
                    page_bytes += len(chunk)
                    total_bytes += len(chunk)

                body = b"".join(chunks).decode(
                    response.encoding or "utf-8",
                    errors="ignore"
                )

                pages += 1
                body_lower = body.lower()

                for keyword in KEYWORDS:
                    if keyword in body_lower:
                        matched_all.add(keyword)

                if "text/html" in content_type:
                    links = re.findall(
                        r'''href\s*=\s*["']([^"']+)["']''',
                        body,
                        re.IGNORECASE
                    )

                    for link in links:
                        next_url = urljoin(current, link.strip())

                        try:
                            parsed = urlparse(next_url)
                            next_host = normalize_host(parsed.hostname)
                        except (ValueError, AttributeError):
                            continue

                        if parsed.scheme in ("http", "https") and next_host == host:
                            if next_url not in seen:
                                queue.append(next_url)

            finally:
                response.close()

        except (requests.RequestException, ValueError) as exc:
            errors.append(str(exc))
            continue

    matched = sorted(matched_all)

    if pages == 0:
        message = "; ".join(errors[:3]) or "Sayfa içeriği okunamadı."
        save_failed_scan(start_url, host, message)
        return "Tarama başarısız", [], message, 0, message

    rating, reason = calculate_rating(matched)

    if rating >= 4:
        status = "Yüksek risk işareti"
    elif rating >= 2:
        status = "İnceleme gerekli"
    else:
        status = "Belirgin işaret bulunamadı"

    note = (
        f"HTTP {http_code}; {pages} sayfa incelendi; "
        f"{total_bytes} bayt veri kontrol edildi."
    )

    if errors:
        note += " Bazı sayfalar incelenemedi."

    with db() as con:
        con.execute("""
            INSERT INTO scans
            (url, domain, checked_at, status, matched, note, rating, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            start_url,
            host,
            now(),
            status,
            ", ".join(matched),
            note,
            rating,
            reason
        ))

    return status, matched, note, rating, reason


@app.before_request
def create_csrf_token():
    if "csrf_token" not in session:
        import secrets
        session["csrf_token"] = secrets.token_hex(32)


def check_csrf():
    token = request.form.get("csrf_token", "")

    if not token or token != session.get("csrf_token"):
        abort(400)


def scan_watchlist():
    if not scan_lock.acquire(blocking=False):
        return 0

    count = 0

    try:
        with db() as con:
            items = con.execute("""
                SELECT * FROM watchlist WHERE enabled=1
            """).fetchall()

        for item in items:
            try:
                scan_one(item["url"])

                with db() as con:
                    con.execute("""
                        UPDATE watchlist SET last_checked=?
                        WHERE id=?
                    """, (now(), item["id"]))

                count += 1

            except Exception:
                app.logger.exception("İzleme adresi taranamadı.")

    finally:
        scan_lock.release()

    return count


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action", "")
        raw = request.form.get("url", "")

        try:
            if action == "scan":
                if not scan_lock.acquire(blocking=False):
                    flash("Başka bir tarama devam ediyor. Biraz bekle.", "error")
                else:
                    try:
                        status, matched, note, rating, reason = scan_one(raw)

                        if rating == 0:
                            flash(
                                f"{status}: {note}",
                                "error"
                            )
                        else:
                            flash(
                                f"{status} | Risk puanı: {rating}/5 | "
                                f"Eşleşmeler: {', '.join(matched) if matched else 'yok'} | {note}",
                                "success"
                            )
                    finally:
                        scan_lock.release()

            elif action == "add":
                url, _ = validate_public_url(raw)

                with db() as con:
                    con.execute(
                        "INSERT OR IGNORE INTO watchlist(url) VALUES(?)",
                        (url,)
                    )

                flash("Adres izleme listesine eklendi.", "success")

            elif action == "scan_watch":
                count = scan_watchlist()
                flash(f"İzleme listesinden {count} adres kontrol edildi.", "success")

            elif action == "toggle":
                item_id = request.form.get("item_id", type=int)

                with db() as con:
                    con.execute("""
                        UPDATE watchlist
                        SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END
                        WHERE id=?
                    """, (item_id,))

                flash("İzleme ayarı güncellendi.", "success")

            elif action == "delete":
                item_id = request.form.get("item_id", type=int)

                with db() as con:
                    con.execute("DELETE FROM watchlist WHERE id=?", (item_id,))

                flash("Adres izleme listesinden silindi.", "success")

            elif action == "reset_stats":
                with db() as con:
                    con.execute("""
                        UPDATE settings
                        SET value=?
                        WHERE name='counter_reset_at'
                    """, (now(),))

                flash(
                    "Sayaçlar sıfırlandı. Eski tarama geçmişin korunuyor.",
                    "success"
                )

        except ValueError as exc:
            flash(str(exc), "error")

        except Exception:
            app.logger.exception("İşlem sırasında hata oluştu.")
            flash("İşlem tamamlanamadı. Lütfen tekrar dene.", "error")

        return redirect(url_for("index"))

    with db() as con:
        reset_row = con.execute("""
            SELECT value FROM settings WHERE name='counter_reset_at'
        """).fetchone()

        reset_at = reset_row["value"] if reset_row else "1970-01-01T00:00:00+00:00"

        scans = con.execute("""
            SELECT * FROM scans ORDER BY id DESC LIMIT 50
        """).fetchall()

        watch = con.execute("""
            SELECT * FROM watchlist ORDER BY id DESC
        """).fetchall()

        total_scans = con.execute("""
            SELECT COUNT(*) FROM scans WHERE checked_at >= ?
        """, (reset_at,)).fetchone()[0]

        high_risk = con.execute("""
            SELECT COUNT(*) FROM scans
            WHERE checked_at >= ? AND rating >= 4
        """, (reset_at,)).fetchone()[0]

    return render_template(
        "index.html",
        scans=scans,
        watch=watch,
        total_scans=total_scans,
        high_risk=high_risk,
        csrf_token=session["csrf_token"]
    )


def automatic_scan_loop():
    while True:
        try:
            time.sleep(60)

            with db() as con:
                row = con.execute("""
                    SELECT value FROM settings
                    WHERE name='last_auto_scan'
                """).fetchone()

            last_scan = row["value"] if row else ""
            should_scan = not last_scan

            if last_scan:
                try:
                    previous = datetime.fromisoformat(last_scan)
                    elapsed = (
                        datetime.now(timezone.utc) - previous
                    ).total_seconds()
                    should_scan = elapsed >= SCAN_INTERVAL
                except ValueError:
                    should_scan = True

            if should_scan:
                count = scan_watchlist()

                with db() as con:
                    con.execute("""
                        UPDATE settings SET value=?
                        WHERE name='last_auto_scan'
                    """, (now(),))

                app.logger.info("Otomatik tarama tamamlandı: %s adres.", count)

        except Exception:
            app.logger.exception("Otomatik tarama hatası.")
            time.sleep(60)


init_db()

if os.environ.get("DISABLE_AUTO_SCAN", "0") != "1":
    threading.Thread(
        target=automatic_scan_loop,
        daemon=True
    ).start()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
