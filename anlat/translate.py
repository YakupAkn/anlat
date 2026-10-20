"""Turns raw sandbox events (strace lines) into plain-language findings."""
import re

# (regex, score, {lang: text})
RULES = [
    (r'(open|openat)\(.*"[^"]*(Login Data|Cookies)"', 30,
     {"en": "Read the browser's saved passwords or cookies.",
      "tr": "Tarayıcının kayıtlı şifrelerini veya çerezlerini okudu."}),
    (r'(open|openat)\(.*"[^"]*(discord)[^"]*"', 25,
     {"en": "Looked for Discord login tokens.",
      "tr": "Discord giriş token'larını aradı."}),
    (r'(open|openat)\(.*"[^"]*(wallet|Exodus|seed)[^"]*"', 30,
     {"en": "Looked for crypto wallet files.",
      "tr": "Kripto cüzdan dosyalarını aradı."}),
    (r'(open|openat)\(.*"[^"]*\.ssh/[^"]*"', 20,
     {"en": "Read SSH keys.", "tr": "SSH anahtarlarını okudu."}),
    (r'(open|openat)\(.*"[^"]*sifreler[^"]*"', 20,
     {"en": "Opened a file that looks like a password list.",
      "tr": "Şifre listesi gibi görünen bir dosyayı açtı."}),
    (r'(open|openat)\(.*"[^"]*(\.bashrc|\.profile|crontab|autostart|systemd)[^"]*".*O_(WR|CREAT|APPEND)', 30,
     {"en": "Tried to make itself start automatically (persistence).",
      "tr": "Kendini otomatik başlatmaya çalıştı (kalıcılık)."}),
    (r'connect\(.*sin_addr=inet_addr\("([\d.]+)"\)', 10,
     {"en": "Tried to connect to a server on the internet.",
      "tr": "İnternetteki bir sunucuya bağlanmaya çalıştı."}),
    (r'execve\("(/bin/sh|/bin/bash|/usr/bin/(curl|wget))"', 10,
     {"en": "Started a shell or a download tool.",
      "tr": "Bir kabuk veya indirme aracı başlattı."}),
    (r'(chmod|fchmodat)\(.*0?7[0-7][0-7]', 5,
     {"en": "Made a file executable.", "tr": "Bir dosyayı çalıştırılabilir yaptı."}),
]

MARKER_RE = re.compile(r"ANLT-[0-9a-f]{8}")
SEND_RE = re.compile(r"^(sendto|write|send)\(\d+,.*ANLT-")


def analyze(trace: str, markers: dict, lang: str = "en"):
    """Returns (score, findings, stolen). findings: list of text. stolen: list of text."""
    findings, seen, score = [], set(), 0
    stolen_read, stolen_sent = set(), set()
    for raw in trace.splitlines():
        line = re.sub(r"^\d+\s+", "", raw)
        for pat, pts, text in RULES:
            if re.search(pat, line) and pat not in seen:
                seen.add(pat)
                score += pts
                findings.append(text[lang])
        for m in MARKER_RE.findall(line):
            if m in markers:
                if SEND_RE.match(line):
                    stolen_sent.add(m)
                elif line.startswith(("read(", "pread")):
                    stolen_read.add(m)
    for m in stolen_sent:
        score += 40
    return min(score, 100), findings, [
        (markers[m], m in stolen_sent) for m in sorted(stolen_read | stolen_sent)
    ]


def risk_label(score: int, lang: str = "en") -> str:
    labels = [(60, {"en": "HIGH RISK", "tr": "YÜKSEK RİSK"}),
              (25, {"en": "SUSPICIOUS", "tr": "ŞÜPHELİ"}),
              (0, {"en": "NO SUSPICIOUS BEHAVIOR SEEN", "tr": "ŞÜPHELİ DAVRANIŞ GÖRÜLMEDİ"})]
    for limit, text in labels:
        if score >= limit:
            return text[lang]
