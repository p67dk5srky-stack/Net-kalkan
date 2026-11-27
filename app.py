
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

def scan_one(raw):
    start_url, host = validate_public_url(raw)

    queue = [start_url]
    seen = set()
    all_matched = set()

    MAX_PAGES = 50
    MAX_PAGE_BYTES = 300_000
    MAX_TOTAL_BYTES = 5_000_000

    pages = 0
    total_bytes = 0
    http_code = "Bilinmiyor"

    while queue and pages < MAX_PAGES and total_bytes < MAX_TOTAL_BYTES:
        current = queue.pop(0)

        try:
            current, current_host = validate_public_url(current)
        except ValueError:
            continue

        if current_host != host:
            continue

        current = urlparse(current)._replace(fragment="").geturl()

        if current in seen:
            continue

        seen.add(current)

        try:
            r = requests.get(
                current,
                headers=HEADERS,
                timeout=8,
                allow_redirects=False,
                stream=True,
                verify=True
            )

            if pages == 0:
                http_code = r.status_code

            chunks = []
            page_bytes = 0

            for chunk in r.iter_content(8192):
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
                r.encoding or "utf-8",
                errors="ignore"
            )

            pages += 1

            all_matched.update(
                k for k in KEYWORDS if k in body.lower()
            )

            content_type = r.headers.get(
                "Content-Type", ""
            ).lower()

            if "text/html" in content_type:
                links = re.findall(
                    r'''href\s*=\s*["']([^"']+)["']''',
                    body,
                    re.IGNORECASE
                )

                for link in links:
                    next_url = urljoin(current, link.strip())
                    parsed = urlparse(next_url)

                    if parsed.scheme not in ("http", "https"):
                        continue

                    if not parsed.hostname:
                        continue

                    try:
                        next_host = parsed.hostname.encode(
                            "idna"
                        ).decode("ascii").lower()
                    except UnicodeError:
                        continue

                    if next_host == host:
                        queue.append(next_url)

            r.close()

        except requests.RequestException:
            continue

    matched = sorted(all_matched)

    status = (
        "İnceleme gerekli"
        if matched
        else "Belirgin işaret bulunamadı"
    )

    note = (
        f"HTTP {http_code}; {pages} sayfa incelendi; "
        f"toplam {total_bytes} bayt tarandı. "
        f"Sayfa sınırı: {MAX_PAGES}."
    )

    checked = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    with db() as con:
        con.execute(
            """INSERT INTO scans
            (url,domain,checked_at,status,matched,note)
            VALUES(?,?,?,?,?,?)""",
            (
                start_url,
                host,
                checked,
                status,
                ", ".join(matched),
                note
            )
        )

    return status, matched, note

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
