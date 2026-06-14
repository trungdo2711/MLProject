from urllib.parse import urlparse
import re
import math
from rapidfuzz import fuzz
import tldextract

SUSPICIOUS_WORDS = ['login', 'secure', 'account', 'update', 'verify', 'bank',
                    'paypal', 'signin', 'confirm', 'password', 'free', 'lucky',
                    'click', 'prize', 'bonus']

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link',
    'win', 'download', 'racing', 'vip', 'club', 'online', 'site',
    'live', 'fun', 'space', 'pw', 'christmas', 'cyou', 'rest',
    'icu', 'cfd', 'hair', 'makeup', 'monster', 'quest', 'skin',
    'football', 'cricket', 'golf', 'soccer', 'rugby', 'basketball',
    'bet', 'casino', 'poker', 'bingo', 'lottery',
}

TRUSTED_DOMAINS = {
    'google.com', 'googleapis.com', 'googleusercontent.com',
    'facebook.com', 'instagram.com', 'youtube.com',
    'microsoft.com', 'office.com', 'live.com',
    'amazon.com', 'amazonaws.com', 'github.com', 'githubusercontent.com',
    'cloudflare.com', 'akamai.com', 'shopee.vn', 'tiki.vn', 'lazada.vn',
    'vietcombank.com.vn', 'bidv.com.vn', 'vnexpress.net', 'tuoitre.vn',
    'dantri.com.vn', 'gov.vn', 'edu.vn', 'zalo.me', 'momo.vn', 'zalopay.vn', 'vlr.gg'
}

FAMOUS_BRANDS = {
    'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
    'vietcombank', 'vcb', 'bidv', 'techcombank', 'agribank',
    'momo', 'zalopay', 'shopee', 'tiki', 'lazada', 'vpbank',
    'mbbank', 'tpbank', 'sacombank', 'viettel', 'vinaphone'
}

SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
    'cutt.ly', 'rebrand.ly', 'bit.do', 'v.gd', 'short.to', 'tiny.cc'
}

# Free hosting platforms often used by attackers for phishing/malware distribution
FREE_HOSTING = {
    'vercel.app', 'netlify.app', 'github.io', 'glitch.me',
    'replit.dev', 'repl.co', '000webhostapp.com', 'web.app',
    'firebaseapp.com', 'pages.dev', 'surge.sh', 'onrender.com',
    'railway.app', 'fly.dev', 'cyclic.app'
}

# Executable / malware-distribution file extensions
EXECUTABLE_EXTENSIONS = {
    '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js',  # Windows
    '.sh', '.elf', '.bin', '.run',                           # Linux generic
    '.i686', '.x86_64', '.aarch64', '.arm',                  # Linux arch-specific RPM/binary
    '.rpm', '.deb', '.pkg',                                   # Package managers
    '.apk', '.ipa',                                           # Mobile
    '.dmg', '.app',                                           # macOS
    '.jar', '.class',                                         # Java
}

def brand_similarity(sld: str) -> float:
    """
    Tính độ tương đồng giữa SLD và các brand nổi tiếng.

    Chiến lược:
    1. Contains-brand: nếu SLD *chứa* tên brand nguyên vẹn (ví dụ "secure-paypal-login"
       chứa "paypal") → đây là dấu hiệu phishing rõ ràng, trả về điểm cao cố định (0.85).
    2. partial_ratio (rapidfuzz): tìm substring khớp tốt nhất trong SLD với brand.
       Thực tế và ít false positive hơn Jaro-Winkler vì không có prefix bonus.
       Score trả về là 0.0–1.0 (từ thang 0–100 của rapidfuzz).
    """
    max_score = 0.0
    for brand in FAMOUS_BRANDS:
        # --- Contains check ---
        if brand in sld and sld != brand:
            # SLD chứa brand nhưng có thêm ký tự → rất có thể là phishing
            max_score = max(max_score, 0.85)
            continue  # đã đạt ngưỡng cao, không cần tính fuzz cho brand này

        # --- rapidfuzz partial_ratio * len_ratio ---
        len_ratio = min(len(sld), len(brand)) / max(len(sld), len(brand))
        if len_ratio < 0.5:
            continue  # quá chênh lệch độ dài, bỏ qua
        score = (fuzz.partial_ratio(sld, brand) / 100.0) * len_ratio
        max_score = max(max_score, score)

    return round(max_score, 4)

_EXTRA_WHITELIST: set = set()
try:
    with open('data/whitelist.txt', encoding='utf-8') as _f:
        for _line in _f:
            _d = _line.strip().lower()
            if _d and not _d.startswith('#'):
                _EXTRA_WHITELIST.add(_d)
            if len(_EXTRA_WHITELIST) >= 5000:
                break
except FileNotFoundError:
    pass

def reload_extra_whitelist():
    global _EXTRA_WHITELIST
    _EXTRA_WHITELIST = set()
    try:
        with open('data/whitelist.txt', encoding='utf-8') as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith('#'):
                    _EXTRA_WHITELIST.add(d)
                if len(_EXTRA_WHITELIST) >= 5000:
                    break
    except FileNotFoundError:
        pass

def is_trusted_domain(hostname: str) -> bool:
    hostname = hostname.lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    # Whitelist check
    for trusted in TRUSTED_DOMAINS | _EXTRA_WHITELIST:
        if hostname == trusted or hostname.endswith('.' + trusted):
            return True
    # Real brand domain check using tldextract (handles eTLDs like workers.dev, co.uk, com.vn)
    ext = tldextract.extract(hostname)
    sld = ext.domain
    tld_leaf = ext.suffix.split('.')[-1] if ext.suffix else ''
    if sld in FAMOUS_BRANDS and tld_leaf not in SUSPICIOUS_TLDS:
        return True
    return False

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def _subdomain_entropy(hostname: str) -> float:
    # Entropy of subdomain to detect random-looking subdomains
    ext = tldextract.extract(hostname)
    subdomain = ext.subdomain
    if not subdomain:
        return 0.0
    return round(shannon_entropy(subdomain), 4)

def _is_uuid_path(path: str, query: str) -> int:
    # Detect if path or query contains a UUID pattern, which is common in C2/malware callback URLs
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return 1 if re.search(uuid_pattern, path.lower()) or re.search(uuid_pattern, query.lower()) else 0

def _subdomain_is_random(hostname: str) -> int:
    ext = tldextract.extract(hostname)
    subdomain = ext.subdomain
    if not subdomain:
        return 0
    # Use the leftmost part of the subdomain (e.g. "small-morning-8be0" from "small-morning-8be0.fsocietyandtools")
    sub = subdomain.split('.')[0]
    if len(sub) < 5 or len(sub) > 20:
        return 0
    vowels = sum(c in 'aeiou' for c in sub)
    vowel_ratio = vowels / len(sub)
    ent = shannon_entropy(sub)

    no_vowels = vowel_ratio == 0.0                    # No vowels at all -> likely random
    high_entropy = vowel_ratio < 0.30 and ent >= 2.4  # High entropy + low vowel ratio -> likely random
    return 1 if (no_vowels or high_entropy) else 0

def extracting_features(url):
    url_lower = str(url).strip().lower()

    clean_url = re.sub(r'^https?://', '', url_lower)
    clean_url = re.sub(r'^www\.', '', clean_url)

    try:
        parsed = urlparse('//' + clean_url)
    except Exception:
        parsed = urlparse('//')

    netloc = parsed.netloc or ''
    path   = parsed.path   or ''
    query  = parsed.query  or ''

    hostname = netloc.split(':')[0] if ':' in netloc else netloc
    has_port = 1 if re.search(r':\d+', netloc) else 0

    # Use tldextract for accurate eTLD parsing (handles workers.dev, github.io, co.uk, etc.)
    ext = tldextract.extract(hostname)
    tld             = ext.suffix                         # e.g. "workers.dev", "com.vn", "co.uk"
    tld_leaf        = tld.split('.')[-1] if tld else ''  # e.g. "dev", "vn", "uk"
    sld             = ext.domain                         # e.g. "fsocietyandtools"
    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0

    n_chars      = len(clean_url) if clean_url else 1
    digit_ratio  = sum(c.isdigit() for c in clean_url) / n_chars
    letter_ratio = sum(c.isalpha() for c in clean_url) / n_chars

    has_suspicious_word = 1 if any(w in url_lower for w in SUSPICIOUS_WORDS) else 0
    has_hex_chars       = 1 if len(re.findall(r'%[0-9a-f]{2}', url_lower)) > 2 else 0
    consecutive_digits  = 1 if re.search(r'\d{4,}', hostname) else 0

    brand_sim = brand_similarity(sld)

    is_shortener     = 1 if hostname in SHORTENERS or any(hostname.endswith('.' + s) for s in SHORTENERS) else 0
    path_digit_ratio = sum(c.isdigit() for c in path) / len(path) if path else 0

    subdomain_entropy = _subdomain_entropy(hostname)

    has_uuid_path = _is_uuid_path(path, query)

    subdomain_is_random = _subdomain_is_random(hostname)

    is_free_hosting = 1 if any(hostname.endswith(h) for h in FREE_HOSTING) else 0
    has_download_param = 1 if (
        'download' in query.lower() or
        'download' in path.lower() or
        'install'  in path.lower()
    ) else 0

    free_hosting_download = 1 if (is_free_hosting and has_download_param) else 0

    # Detect executable/malware file extensions in path
    import os
    path_ext = os.path.splitext(path.lower())[1]  # e.g. '.i686', '.exe', '.sh'
    has_executable_ext = 1 if path_ext in EXECUTABLE_EXTENSIONS else 0

    features = {
        'url_len':            len(clean_url),
        'domain_len':         len(netloc),
        'path_len':           len(path),
        'count_dot':          clean_url.count('.'),
        'count_hyphen':       clean_url.count('-'),
        'count_at':           clean_url.count('@'),
        'count_slash':        clean_url.count('/'),
        'count_question':     clean_url.count('?'),
        'count_equal':        clean_url.count('='),
        'is_ip':              1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'shannon_entropy':    round(shannon_entropy(hostname), 4),
        'digit_ratio':        round(digit_ratio, 4),
        'letter_ratio':       round(letter_ratio, 4),
        'subdomain_count':    subdomain_count,
        'domain_digit_count': sum(c.isdigit() for c in hostname),
        'tld_suspicious':     1 if tld_leaf in SUSPICIOUS_TLDS else 0,
        'count_percent':      clean_url.count('%'),
        'count_ampersand':    query.count('&'),
        'path_depth':         path.count('/'),
        'has_port':                has_port,
        'has_hex_chars':           has_hex_chars,
        'has_suspicious_word':     has_suspicious_word,
        'consecutive_digits':      consecutive_digits,
        'brand_similarity':        brand_sim,
        'is_shortener':            is_shortener,
        'path_digit_ratio':        round(path_digit_ratio, 4),
        'subdomain_entropy':       subdomain_entropy,
        'has_uuid_path':           has_uuid_path,
        'subdomain_is_random':     subdomain_is_random,
        'is_free_hosting':         is_free_hosting,
        'has_download_param':      has_download_param,
        'free_hosting_download':   free_hosting_download,
        'has_executable_ext':      has_executable_ext,
    }
    return features


def generate_whitelist(
    src:     str = 'data/top-1m.csv',
    dst:     str = 'data/whitelist.txt',
    top_n:   int = 10000,
    max_out: int = 5000,
):
    count = 0
    with open(src, encoding='utf-8') as f_in, \
         open(dst, 'w', encoding='utf-8') as f_out:
        f_out.write("# Auto-generated from Tranco top 1M\n")
        for i, line in enumerate(f_in):
            if i >= top_n or count >= max_out:
                break
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            if len(parts) < 2:
                continue
            domain = parts[1].lower()
            tld    = domain.split('.')[-1]
            if tld in SUSPICIOUS_TLDS:
                continue
            f_out.write(domain + '\n')
            count += 1
    print(f"Done — {count} domains saved to {dst}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--src',     default='data/top-1m.csv')
    parser.add_argument('--dst',     default='data/whitelist.txt')
    parser.add_argument('--top_n',   type=int, default=10000)
    parser.add_argument('--max_out', type=int, default=5000)
    args = parser.parse_args()
    generate_whitelist(args.src, args.dst, args.top_n, args.max_out)