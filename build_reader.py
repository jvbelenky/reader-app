#!/usr/bin/env python3
"""Build the reader site.

Drop books into ./books (PDF, EPUB, TXT, MD), run this, commit ./docs, push.

  docs/index.html, app.css, app.js, sw.js, manifest, icons   (copied from ./app)
  docs/meta.json          key-derivation salt + a passphrase check value
  docs/library.bin        encrypted library index (titles, chapters, word counts)
  docs/books/<id>.bin     encrypted reflowed book body; <id> is an opaque hash

Everything under docs/ is safe to publish: book text and titles are AES-256-GCM
encrypted with a key derived from your passphrase (PBKDF2-SHA256). The passphrase
and salt live in .reader.json, which is gitignored. The books/ folder is gitignored too.
"""
import base64, getpass, hashlib, hmac, html, json, os, re, secrets, shutil, statistics, sys, time, zipfile
from collections import Counter
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
BOOKS = os.path.join(HERE, "books")
APP = os.path.join(HERE, "app")
DIST = os.path.join(HERE, "docs")          # committed; GitHub Pages serves this folder
CONFIG = os.path.join(HERE, ".reader.json")  # local only: passphrase + salt
PBKDF2_ITER = 300_000
FORMATS = (".pdf", ".epub", ".txt", ".md")


# =============================================================== common model
# A book is a list of chapters: {"title": str, "blocks": [{"t":"p","h":html} | {"t":"br"}]}

class Builder:
    """Accumulates paragraphs/headings/breaks into chapters."""

    def __init__(self):
        self.chapters = []
        self.cur = None

    def heading(self, title):
        title = re.sub(r"\s+", " ", title).strip()
        if self.cur is not None and not self.cur["blocks"] and self.cur["title"]:
            # two heading lines in a row: join them
            self.cur["title"] += " " + title
            return
        self.cur = {"title": title, "blocks": []}
        self.chapters.append(self.cur)

    def para(self, h):
        h = re.sub(r"\s+", " ", h).strip()
        h = h.replace("</i> <i>", " ").replace("</b> <b>", " ")
        if not h:
            return
        if self.cur is None:
            self.cur = {"title": "", "blocks": []}
            self.chapters.append(self.cur)
        self.cur["blocks"].append({"t": "p", "h": h})

    def brk(self):
        if self.cur and self.cur["blocks"] and self.cur["blocks"][-1]["t"] != "br":
            self.cur["blocks"].append({"t": "br"})

    def finish(self):
        out = []
        for c in self.chapters:
            while c["blocks"] and c["blocks"][-1]["t"] == "br":
                c["blocks"].pop()
            if c["blocks"] or c["title"]:
                out.append(c)
        return out


# =============================================================== PDF
def extract_pdf(path):
    import fitz  # PyMuPDF

    doc = fitz.open(path)
    meta = doc.metadata or {}
    pages = []           # list of pages; page = list of line dicts
    size_count = Counter()
    for pno, page in enumerate(doc):
        W, H = page.rect.width, page.rect.height
        lines = []
        for b in page.get_text("dict")["blocks"]:
            if b["type"] != 0:
                continue
            for l in b["lines"]:
                spans = [s for s in l["spans"] if s["text"].strip()]
                if not spans:
                    continue
                txt = "".join(s["text"] for s in spans).strip()
                x0, y0, x1, y1 = l["bbox"]
                size = max(s["size"] for s in spans)
                for s in spans:
                    size_count[round(s["size"], 1)] += len(s["text"])
                lines.append(dict(x0=x0, y0=y0, x1=x1, y1=y1, spans=spans, txt=txt, size=size,
                                  bold=all(_bold(s) for s in spans), W=W, H=H))
        lines.sort(key=lambda l: (round(l["y0"] / 3), l["x0"]))
        pages.append(lines)
    if not size_count:
        raise ValueError("no text layer (scanned PDF?)")
    body_size = size_count.most_common(1)[0][0]

    # Line pitch: median vertical step between consecutive body lines.
    steps = []
    for lines in pages:
        for a, b in zip(lines, lines[1:]):
            d = b["y0"] - a["y0"]
            if 2 < d < 80:
                steps.append(d)
    pitch = statistics.median(steps) if steps else body_size * 1.4

    # Body left margin: most common x0 among body-size lines.
    body_lines = [l for lines in pages for l in lines if abs(l["size"] - body_size) < 0.6]
    xc = Counter(round(l["x0"]) for l in body_lines)
    common = [x for x, n in xc.items() if n >= 0.08 * len(body_lines)]
    margin = min(common) if common else (xc.most_common(1)[0][0] if xc else 0)

    # Running headers/footers: text repeating at the top/bottom of many pages.
    def norm(t):
        return re.sub(r"\d+", "#", t.lower()).strip()
    edge = Counter()
    for lines in pages:
        for l in lines[:2] + lines[-2:]:
            edge[norm(l["txt"])] += 1
    repeated = {t for t, n in edge.items() if n >= max(3, 0.3 * len(pages))}
    roman = re.compile(r"^[ivxlcdm]+$", re.I)

    def is_furniture(l, i, n):
        near_edge = l["y0"] < l["H"] * 0.12 or l["y1"] > l["H"] * 0.88
        if not near_edge:
            return False
        t = l["txt"]
        styled = l["bold"] or l["size"] >= body_size * 1.18   # page numbers are plain; styled numerals are headings
        if not styled and (re.fullmatch(r"[\s\d\-–—|.]+", t) or roman.match(t) or re.fullmatch(r"(page\s*)?\d+(\s*(of|/)\s*\d+)?", t, re.I)):
            return True
        return norm(t) in repeated and (i < 2 or i >= n - 2)

    # Vocabulary for de-hyphenation decisions.
    vocab = set()
    for l in body_lines:
        for w in re.findall(r"[A-Za-z]+", l["txt"]):
            vocab.add(w.lower())

    indented = [l for l in body_lines if margin + 6 < l["x0"] < margin + 90 and not _centered(l)]
    indent_style = 0.04 < len(indented) / max(1, len(body_lines)) < 0.7

    B = Builder()
    para = None     # list of html line fragments
    prev = None     # previous body line (any page)
    hyph_prev = False

    def flush():
        nonlocal para
        if para:
            B.para(_join_lines(para, vocab))
        para = None

    for lines in pages:
        n = len(lines)
        page_prev = None
        for i, l in enumerate(lines):
            if is_furniture(l, i, n):
                continue
            gap = (l["y0"] - page_prev["y0"]) if page_prev else None
            heading = _is_heading(l, body_size, margin, pitch, lines, i)
            if heading:
                flush()
                B.heading(l["txt"])
                page_prev = l; prev = l
                continue
            frag = "".join(_span_html(s) for s in l["spans"]).strip()
            first_on_page = page_prev is None
            is_indent = margin + 6 < l["x0"] < margin + 90 and not _centered(l)
            if indent_style:
                if gap is not None and gap > pitch * 1.6:
                    flush(); B.brk()
                if is_indent or _centered(l) and not para:
                    flush(); para = [frag]
                elif para is None:
                    para = [frag]
                else:
                    para.append(frag)
            else:
                new_para = False
                if gap is not None and gap > pitch * 2.6:
                    flush(); B.brk(); new_para = True
                elif gap is not None and gap > pitch * 1.3:
                    new_para = True
                elif first_on_page and prev is not None and re.search(r"[.!?…\"”’')\]]\s*$", prev["txt"]):
                    new_para = True
                elif first_on_page and prev is None:
                    new_para = True
                if new_para or para is None:
                    flush(); para = [frag]
                else:
                    para.append(frag)
            page_prev = l; prev = l
    flush()

    title = (meta.get("title") or "").strip()
    if not title or re.search(r"\.(docx?|odt|pdf|txt)$", title, re.I) or title.lower() in ("untitled", "microsoft word"):
        title = ""
    author = (meta.get("author") or "").strip()
    return B.finish(), title, author


def _bold(s):
    return "bold" in s["font"].lower() or bool(s.get("flags", 0) & 16)


def _italic(s):
    f = s["font"].lower()
    return "italic" in f or "oblique" in f or bool(s.get("flags", 0) & 2)


def _centered(l):
    mid = (l["x0"] + l["x1"]) / 2
    return abs(mid - l["W"] / 2) < l["W"] * 0.06 and l["x0"] > l["W"] * 0.2


def _is_heading(l, body_size, margin, pitch, lines, i):
    t = l["txt"]
    if len(t) > 90 or not re.search(r"[A-Za-z0-9]", t):
        return False
    if l["size"] >= body_size * 1.18:
        return True
    if l["bold"]:
        nxt = lines[i + 1] if i + 1 < len(lines) else None
        prv = lines[i - 1] if i > 0 else None
        gap_after = (nxt["y0"] - l["y0"]) if nxt else pitch * 3
        gap_before = (l["y0"] - prv["y0"]) if prv else pitch * 3
        if _centered(l) and len(t) <= 60:
            return True
        isolated = gap_after > pitch * 1.3 and gap_before > pitch * 1.3
        if abs(l["x0"] - margin) < 4 and isolated and len(t) <= 60 and not re.search(r"[.,;:?!\"\u201d\u2019']$", t):
            return True
    return False


def _span_html(s):
    t = html.escape(s["text"])
    if s.get("flags", 0) & 1 or s["size"] < 7.5:
        return f"<sup>{t}</sup>"
    if _bold(s) and _italic(s):
        return f"<b><i>{t}</i></b>"
    if _italic(s):
        return f"<i>{t}</i>"
    if _bold(s):
        return f"<b>{t}</b>"
    return t


def _join_lines(frags, vocab):
    """Join PDF lines into one paragraph, deciding hyphen breaks with the document's own vocabulary."""
    text = ""
    for i, ln in enumerate(frags):
        if i == 0:
            text = ln
            continue
        m = re.search(r"([A-Za-z]+)-$", text)
        n = re.match(r"([a-z]+)", ln)
        if m and n:
            joined = (m.group(1) + n.group(1)).lower()
            if joined in vocab:
                text = text[:-1] + ln        # soft hyphen: "sud-" + "denly" -> suddenly
            else:
                text = text + ln             # real compound: "great-" + "grandmother"
        else:
            text = text + " " + ln
    return text


# =============================================================== EPUB
class _XHTMLToBlocks(HTMLParser):
    BLOCK = {"p", "div", "li", "blockquote", "pre", "dd", "dt", "td", "th", "figcaption", "section", "article", "aside"}
    HEAD = {"h1", "h2", "h3"}
    SKIP = {"script", "style", "head", "title", "nav", "svg", "img", "sup:skip"}

    def __init__(self, B):
        super().__init__(convert_charrefs=True)
        self.B = B; self.buf = []; self.skip = 0; self.inhead = None; self.fmt = []

    def _flush(self):
        h = "".join(self.buf).strip()
        self.buf = []
        if self.inhead is not None:
            if re.sub("<[^>]+>", "", h).strip():
                self.B.heading(re.sub("<[^>]+>", "", h))
        elif h:
            self.B.para(h)

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1; return
        if self.skip:
            return
        if tag in self.HEAD:
            self._flush(); self.inhead = tag
        elif tag in self.BLOCK:
            self._flush()
        elif tag == "hr":
            self._flush(); self.B.brk()
        elif tag == "br":
            self.buf.append(" ")
        elif tag in ("i", "em", "cite"):
            self.buf.append("<i>"); self.fmt.append("</i>")
        elif tag in ("b", "strong"):
            self.buf.append("<b>"); self.fmt.append("</b>")
        elif tag == "sup":
            self.buf.append("<sup>"); self.fmt.append("</sup>")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1); return
        if self.skip:
            return
        if tag in self.HEAD:
            self._flush(); self.inhead = None
        elif tag in self.BLOCK:
            self._flush()
        elif tag in ("i", "em", "cite", "b", "strong", "sup") and self.fmt:
            self.buf.append(self.fmt.pop())

    def handle_data(self, data):
        if not self.skip:
            self.buf.append(html.escape(data))

    def close(self):
        super().close(); self._flush()


def extract_epub(path):
    ns = {"c": "urn:oasis:names:tc:opendocument:xmlns:container", "o": "http://www.idpf.org/2007/opf", "dc": "http://purl.org/dc/elements/1.1/"}
    with zipfile.ZipFile(path) as z:
        container = ET.fromstring(z.read("META-INF/container.xml"))
        opf_path = container.find(".//c:rootfile", ns).get("full-path")
        opf = ET.fromstring(z.read(opf_path))
        base = os.path.dirname(opf_path)
        title = (opf.findtext(".//dc:title", default="", namespaces=ns) or "").strip()
        author = (opf.findtext(".//dc:creator", default="", namespaces=ns) or "").strip()
        items = {it.get("id"): it for it in opf.find("o:manifest", ns)}
        B = Builder()
        for ref in opf.find("o:spine", ns):
            it = items.get(ref.get("idref"))
            if it is None or "html" not in (it.get("media-type") or ""):
                continue
            href = os.path.normpath(os.path.join(base, it.get("href"))).replace("\\", "/")
            try:
                raw = z.read(href).decode("utf-8", "replace")
            except KeyError:
                continue
            p = _XHTMLToBlocks(B); p.feed(raw); p.close()
    return B.finish(), title, author


# =============================================================== TXT / MD
def extract_text(path):
    raw = open(path, encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    B = Builder()
    title = ""
    for chunk in re.split(r"\n\s*\n", raw):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"^(#{1,3})\s+(.+)$", chunk)
        if m:
            if not title and m.group(1) == "#":
                title = m.group(2).strip()
            B.heading(m.group(2)); continue
        if re.fullmatch(r"(\*\s*){3,}|-{3,}|_{3,}|#+", chunk):
            B.brk(); continue
        if len(chunk) < 80 and "\n" not in chunk and re.match(r"^(chapter|part|book|prologue|epilogue|interlude)\b", chunk, re.I):
            B.heading(chunk); continue
        h = html.escape(chunk)
        h = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", h)
        h = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<i>\1</i>", h)
        h = re.sub(r"(?<![A-Za-z0-9])_(?!\s)(.+?)(?<!\s)_(?![A-Za-z0-9])", r"<i>\1</i>", h)
        B.para(h.replace("\n", " "))
    return B.finish(), title, ""


# =============================================================== crypto
def load_config():
    cfg = {}
    if os.path.exists(CONFIG):
        cfg = json.load(open(CONFIG))
    if not cfg.get("salt"):
        cfg["salt"] = base64.b64encode(secrets.token_bytes(16)).decode()
    pw = cfg.get("password") or os.environ.get("READER_PASSWORD")
    if not pw:
        if not sys.stdin.isatty():
            sys.exit("No passphrase: put it in .reader.json as {\"password\": ...} or set READER_PASSWORD.")
        pw = getpass.getpass("Choose the reader passphrase (saved to .reader.json): ")
        if not pw:
            sys.exit("Empty passphrase.")
    cfg["password"] = pw
    with open(CONFIG, "w") as f:
        json.dump(cfg, f, indent=1)
    try:
        os.chmod(CONFIG, 0o600)
    except OSError:
        pass
    return cfg


def derive_key(password, salt_b64):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), PBKDF2_ITER, 32)


def encrypt(key, plaintext, aad):
    """AES-256-GCM. The IV is derived from the content so unchanged books produce
    unchanged ciphertext and git history stays small; a key/plaintext pair is never
    encrypted under two different IVs, so the derivation is safe."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = hmac.new(key, hashlib.sha256(plaintext).digest() + aad, "sha256").digest()[:12]
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def write_if_changed(path, data):
    if os.path.exists(path) and open(path, "rb").read() == data:
        return False
    with open(path, "wb") as f:
        f.write(data)
    return True


# =============================================================== build
def slugify(name):
    s = re.sub(r"\[.*?\]|\(.*?\)", "", name)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s or "book"


def pretty_title(stem):
    s = re.sub(r"\[.*?\]", "", stem)
    s = re.sub(r"[_]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or stem


def load_overrides():
    """Optional books/meta.json: {"file name.pdf": {"title": "...", "author": "..."}}"""
    p = os.path.join(BOOKS, "meta.json")
    try:
        return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
    except ValueError as e:
        print(f"  ! books/meta.json is not valid JSON ({e}); ignoring", file=sys.stderr)
        return {}


def book_html(chapters):
    parts = []
    for ci, c in enumerate(chapters, 1):
        title = c["title"] or f"Part {ci}"
        parts.append(f'<section class="ch" id="ch{ci}" data-title="{html.escape(title)}">')
        if c["title"]:
            parts.append(f'<h2><span class="chname">{html.escape(c["title"])}</span></h2>')
        for b in c["blocks"]:
            parts.append(f'<p>{b["h"]}</p>' if b["t"] == "p" else "<hr>")
        parts.append("</section>")
    return "\n".join(parts)


def build():
    cfg = load_config()
    key = derive_key(cfg["password"], cfg["salt"])
    os.makedirs(os.path.join(DIST, "books"), exist_ok=True)
    library, keep = [], set()
    overrides = load_overrides()
    files = sorted(f for f in os.listdir(BOOKS) if f.lower().endswith(FORMATS)) if os.path.isdir(BOOKS) else []
    for fn in files:
        path = os.path.join(BOOKS, fn)
        stem, ext = os.path.splitext(fn)
        ext = ext.lower()
        try:
            if ext == ".pdf":
                chapters, title, author = extract_pdf(path)
            elif ext == ".epub":
                chapters, title, author = extract_epub(path)
            else:
                chapters, title, author = extract_text(path)
        except Exception as e:  # keep building the rest of the shelf
            print(f"  ! {fn}: {e}", file=sys.stderr)
            continue
        if not chapters:
            print(f"  ! {fn}: no text found", file=sys.stderr)
            continue
        book_id = hashlib.sha1((cfg["salt"] + slugify(stem)).encode()).hexdigest()[:12]
        words = sum(len(re.sub("<[^>]+>", "", b["h"]).split()) for c in chapters for b in c["blocks"] if b["t"] == "p")
        body = book_html(chapters).encode("utf-8")
        changed = write_if_changed(os.path.join(DIST, "books", book_id + ".bin"), encrypt(key, body, b"book:" + book_id.encode()))
        keep.add(book_id + ".bin")
        ov = overrides.get(fn, {})
        library.append({
            "id": book_id, "title": ov.get("title") or title or pretty_title(stem), "author": ov.get("author") or author,
            "words": words, "chapters": [c["title"] for c in chapters if c["title"]],
            "format": ext[1:], "added": int(os.path.getmtime(path)),
        })
        print(f"  {fn}: {len(chapters)} chapters, {words} words -> books/{book_id}.bin{'' if changed else ' (unchanged)'}")
    for fn in os.listdir(os.path.join(DIST, "books")):
        if fn.endswith(".bin") and fn not in keep:
            os.remove(os.path.join(DIST, "books", fn))
            print(f"  removed stale books/{fn}")
    library.sort(key=lambda b: b["title"].lower())
    lib_bytes = json.dumps({"built": max([b["added"] for b in library] or [0]), "books": library}, ensure_ascii=False).encode("utf-8")
    lib_enc = encrypt(key, lib_bytes, b"library")
    write_if_changed(os.path.join(DIST, "library.bin"), lib_enc)
    meta = {"salt": cfg["salt"], "iter": PBKDF2_ITER,
            "check": base64.b64encode(encrypt(key, b"reader-ok", b"check")).decode()}
    write_if_changed(os.path.join(DIST, "meta.json"), json.dumps(meta).encode())

    # App shell, with a build version stamped into the service worker.
    for fn in os.listdir(APP):
        if fn != "sw.js":
            shutil.copy(os.path.join(APP, fn), os.path.join(DIST, fn))
    h = hashlib.sha1()
    for fn in sorted(os.listdir(APP)):
        h.update(open(os.path.join(APP, fn), "rb").read())
    h.update(lib_enc)
    ver = h.hexdigest()[:10]
    sw = open(os.path.join(APP, "sw.js"), encoding="utf-8").read().replace("__VERSION__", ver)
    write_if_changed(os.path.join(DIST, "sw.js"), sw.encode())
    make_icons()
    print(f"library: {len(library)} books, version {ver}")


def make_icons():
    try:
        import fitz
    except ImportError:
        return
    for size in (192, 512):
        out = os.path.join(DIST, f"icon-{size}.png")
        if os.path.exists(out):
            continue
        d = fitz.open()
        page = d.new_page(width=size, height=size)
        sh = page.new_shape()
        sh.draw_rect(fitz.Rect(0, 0, size, size)); sh.finish(fill=(0.07, 0.08, 0.09), color=None); sh.commit()
        m = size * 0.2
        sh = page.new_shape()
        sh.draw_polyline([fitz.Point(m, size * 0.32), fitz.Point(size / 2, size * 0.4), fitz.Point(size / 2, size * 0.78), fitz.Point(m, size * 0.7), fitz.Point(m, size * 0.32)])
        sh.draw_polyline([fitz.Point(size - m, size * 0.32), fitz.Point(size / 2, size * 0.4), fitz.Point(size / 2, size * 0.78), fitz.Point(size - m, size * 0.7), fitz.Point(size - m, size * 0.32)])
        sh.finish(fill=(0.84, 0.83, 0.80), color=(0.07, 0.08, 0.09), width=size * 0.012, closePath=True); sh.commit()
        page.get_pixmap(dpi=72).save(out)


if __name__ == "__main__":
    build()
