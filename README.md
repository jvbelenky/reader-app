# Reader

A private, mobile-first reading app for your own documents. Drop books in, read them anywhere, pick up where you left off.

## Adding a book

1. Put a `.pdf`, `.epub`, `.txt`, or `.md` file in `books/`.
2. Run `./publish.sh`. It rebuilds, commits the encrypted output in `docs/`, and pushes.
3. About a minute later the book is on the shelf.

The first build asks you to choose a passphrase and stores it in `.reader.json` (gitignored, along with `books/`). Only encrypted files ever reach GitHub.

## Reading

Open the site and enter the passphrase once per device. Tap a book. Text size, spacing, font, and theme live in the "Aa" sheet. Your position in each book is saved on the device and restored to the exact line. Books you've opened once work offline. "Lock now" in settings forgets the key on that device.

## How the privacy works

- Book text and the library index are encrypted with AES-256-GCM. The key comes from your passphrase through PBKDF2-SHA256 (300,000 rounds, random salt).
- File names in `docs/books/` are opaque hashes, so titles aren't visible either.
- The browser keeps the derived key in IndexedDB as a non-extractable key. The passphrase itself is never stored in the browser.
- What is public: the app shell (HTML, CSS, JS), the salt, and the sizes of the encrypted files.
- Pick a passphrase you'd trust against offline guessing: a few random words is plenty.

## Local preview

```
pip install pymupdf cryptography
python build_reader.py
python -m http.server -d docs 8000
```

Layout: `app/` is the static shell, `build_reader.py` extracts and encrypts books into `docs/`.

Extraction notes: PDFs need a real text layer (scans won't work). Paragraphs come from indents or blank-line gaps, chapter headings from larger or bold standalone lines, and running headers, footers, and page numbers are removed. Single-column text like manuscripts, novels, and reports comes out clean; multi-column layouts will be rougher. EPUB is the cleanest source.
