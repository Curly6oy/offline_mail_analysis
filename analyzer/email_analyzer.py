from email import policy
from email.parser import BytesParser
from hashlib import sha256
import re
from html import unescape
from urllib.parse import urlparse

MAX_EMAIL_SIZE = 10 * 1024 * 1024

PATTERNS = [
    ("Email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("Телефон", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)")),
    ("Паспорт РФ", re.compile(r"\b\d{4}\s?\d{6}\b")),
    ("СНИЛС", re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b")),
    ("ИНН", re.compile(r"\b\d{10}(?:\d{2})?\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.I)),
    ("IPv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("Дата рождения", re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)\d{2}\b")),
]
NAME_PATTERN = re.compile(r"(?<!\w)(?:[А-ЯЁ][а-яё]+\s+){1,2}[А-ЯЁ][а-яё]+(?!\w)")
URL_PATTERN = re.compile(r"https?://[^\s<>\"]+", re.I)


def _luhn(value):
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        n = int(digit)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _find_card_numbers(text):
    candidates = re.findall(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text)
    return sum(_luhn(x) for x in candidates)


def _parts(message):
    plain, html, attachments = [], [], []
    for part in message.walk():
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({"content_type": ctype, "size": len(payload), "sha256": sha256(payload).hexdigest()})
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                text = part.get_content()
            except (LookupError, UnicodeDecodeError):
                text = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            (plain if ctype == "text/plain" else html).append(text)
    return "\n".join(plain), "\n".join(html), attachments


def _pii(text):
    counts = {}
    for kind, pattern in PATTERNS:
        counts[kind] = len(pattern.findall(text))
    counts["Банковская карта"] = _find_card_numbers(text)
    counts["ФИО/имя"] = len(NAME_PATTERN.findall(text))
    return [{"type": k, "count": v} for k, v in counts.items() if v]


def _urls(text):
    result = []
    seen = set()
    for raw in URL_PATTERN.findall(text):
        parsed = urlparse(raw.rstrip(".,);]}>"))
        if parsed.scheme and parsed.hostname and parsed.hostname.lower() not in seen:
            seen.add(parsed.hostname.lower())
            result.append({"host": parsed.hostname.lower(), "scheme": parsed.scheme.lower()})
    return result[:100]


def _headers(message):
    findings = []
    sender = str(message.get("From", "")).strip().lower()
    reply = str(message.get("Reply-To", "")).strip().lower()
    if sender and reply and sender != reply:
        findings.append("From и Reply-To различаются")
    if len(message.get_all("Received", [])) > 1:
        findings.append("В письме присутствует цепочка Received")
    auth = " ".join(message.get_all("Authentication-Results", [])).lower()
    for method in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{method}\s*=\s*fail\b", auth):
            findings.append(f"В Authentication-Results обнаружен {method.upper()} fail")
    return findings


def analyze_eml(raw_bytes, filename="message.eml"):
    if len(raw_bytes) > MAX_EMAIL_SIZE:
        raise ValueError("Файл превышает максимальный размер 10 МБ")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:
        raise ValueError("Некорректный email/MIME файл") from exc

    plain, html, attachments = _parts(message)
    html_text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", unescape("\n".join([
        str(message.get("Subject", "")), str(message.get("From", "")),
        str(message.get("To", "")), str(message.get("Cc", "")), plain, html_text,
    ]))).strip()

    pii = _pii(text)
    urls = _urls(text)
    headers = _headers(message)
    pii_count = sum(x["count"] for x in pii)
    score = min(100, pii_count * 8 + len(urls) * 2 + len(attachments) * 8 + len(headers) * 5)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"

    return {
        "privacy": {"offline": True, "external_requests": False, "raw_pii_in_report": False},
        "message": {
            "subject_present": bool(message.get("Subject")),
            "from_present": bool(message.get("From")),
            "to_present": bool(message.get("To")),
            "date_present": bool(message.get("Date")),
        },
        "pii": pii,
        "urls": urls,
        "attachments": attachments,
        "header_findings": headers,
        "risk": {"score": score, "level": level},
    }
