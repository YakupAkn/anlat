"""Writes a single self-contained HTML report."""
import html

T = {
    "en": {"title": "What does this file do?", "file": "File", "size": "Size",
           "hash": "SHA-256", "behavior": "Behavior seen in the sandbox",
           "none": "Nothing suspicious was observed.", "stolen": "What would have been stolen on a real PC",
           "read": "read", "sent": "read AND tried to send out", "static": "Static clues",
           "urls": "URLs inside the file", "kw": "Suspicious words",
           "note": "Limits: a clever program can detect sandboxes and stay quiet. "
                   "A clean report is not a guarantee."},
    "tr": {"title": "Bu dosya ne yapıyor?", "file": "Dosya", "size": "Boyut",
           "hash": "SHA-256", "behavior": "Sandbox'ta görülen davranışlar",
           "none": "Şüpheli bir şey görülmedi.", "stolen": "Gerçek bilgisayarda çalınacak veriler",
           "read": "okudu", "sent": "okudu VE dışarı göndermeye çalıştı", "static": "Statik ipuçları",
           "urls": "Dosyanın içindeki URL'ler", "kw": "Şüpheli kelimeler",
           "note": "Sınır: akıllı bir program sandbox'ı fark edip sessiz kalabilir. "
                   "Temiz rapor garanti değildir."},
}


def render(info, score, label, findings, stolen, lang="en") -> str:
    t = T[lang]
    e = html.escape
    color = "#c0392b" if score >= 60 else "#e67e22" if score >= 25 else "#27ae60"
    li = "".join(f"<li>{e(f)}</li>" for f in findings) or f"<li>{t['none']}</li>"
    st = "".join(f"<li>{e(d)}: <b>{t['sent'] if sent else t['read']}</b></li>" for d, sent in stolen)
    st_block = f"<h2>{t['stolen']}</h2><ul>{st}</ul>" if st else ""
    urls = "".join(f"<li><code>{e(u)}</code></li>" for u in info["urls"])
    urls_block = f"<h3>{t['urls']}</h3><ul>{urls}</ul>" if urls else ""
    kw = ", ".join(e(k) for k in info["keywords"])
    kw_block = f"<h3>{t['kw']}</h3><p>{kw}</p>" if kw else ""
    return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<title>Anlat</title><style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#222}}
.badge{{display:inline-block;padding:.5rem 1rem;border-radius:8px;color:#fff;background:{color};font-weight:700}}
code{{background:#f2f2f2;padding:2px 4px;border-radius:4px;word-break:break-all}}
.meta{{color:#666;font-size:.9rem}} .note{{margin-top:2rem;color:#777;font-size:.85rem}}
</style></head><body>
<h1>{t['title']}</h1>
<p class="badge">{e(label)} ({score}/100)</p>
<p class="meta">{t['file']}: {e(info['name'])} | {t['size']}: {info['size']} B<br>{t['hash']}: <code>{info['sha256']}</code></p>
<h2>{t['behavior']}</h2><ul>{li}</ul>
{st_block}
<h2>{t['static']}</h2>{urls_block}{kw_block}
<p class="note">{t['note']}</p></body></html>"""
