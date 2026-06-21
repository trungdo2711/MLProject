import re
from urllib.parse import urlparse, unquote_plus
import tldextract
from collections import Counter
from math import log2, floor
import ipaddress
from rapidfuzz.distance import Levenshtein
SCHEME = 0
NETLOC = 1
USERNAME = 2
PASSWORD = 3
PORT = 4
SUBDOMAIN = 5
DOMAIN = 6
SUFFIX = 7
PATH = 8
PARAMS = 9
QUERY = 10
FRAGMENT = 11
VOWELS = set('aeiouAEIOU')
SUSPICIOUS_KEYWORDS = {
    # authentication
    'login', 'signin', 'sign-in', 'log-in',
    'logout', 'signout',
    # account
    'account', 'myaccount', 'profile', 'user',
    # security
    'secure', 'security', 'verify', 'verification',
    'validate', 'validation', 'confirm', 'confirmation',
    # financial
    'banking', 'payment', 'checkout', 'billing',
    'invoice', 'wallet', 'transaction',
    # urgency
    'update', 'urgent', 'alert', 'warning', 'notice',
    'suspend', 'suspended', 'limited', 'unlock',
    # support
    'support', 'helpdesk', 'recover', 'recovery',
    'reset', 'password', 'credential',
    # webmail
    'webmail', 'outlook', 'office365', 'cpanel',
}
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link',
    'win', 'download', 'racing', 'vip', 'club', 'online', 'site',
    'live', 'fun', 'space', 'pw', 'christmas', 'cyou', 'rest',
    'icu', 'cfd', 'hair', 'makeup', 'monster', 'quest', 'skin',
}
SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
    'cutt.ly', 'rebrand.ly', 'bit.do', 'v.gd', 'short.to', 'tiny.cc'
}
FREE_HOSTING = {
    'vercel.app', 'netlify.app', 'github.io', 'glitch.me',
    'replit.dev', 'repl.co', '000webhostapp.com', 'web.app',
    'firebaseapp.com', 'pages.dev', 'surge.sh', 'onrender.com',
    'railway.app', 'fly.dev', 'cyclic.app'
}
PROTOCOLS = {'HTTP', 'HTTPS', 'FTP', 'FTPS'}
PORTS = {80, 443, 8080, 21}
url_structure = [SCHEME, NETLOC, PATH, QUERY, FRAGMENT]
def url_length(url : str) -> int:
    return len(url)
def fully_decode(data : str) -> str:
    if not data:
        return ""
    current = str(data)
    while True:
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return current
def normalize_url(url: str) -> str:
    if re.match(r'^[a-zA-Z][a-zA-Z0-9\+\-\.]*://', url):
        return url
    if url.startswith('//'):
        return url
    return '//' + url
def extract_url(url : str) -> list:
    url = str(url).strip()
    normalized = normalize_url(url)
    extracted = tldextract.extract(normalized)
    try:
        parsed = urlparse(normalized)
        scheme = urlparse(url).scheme if '://' in url else ''
    except ValueError:
        from urllib.parse import ParseResult
        parsed = ParseResult('', '', '', '', '', '')
        scheme = ''

    try:
        port_number = parsed.port
    except ValueError:
        port_number = None
    decoded_username = fully_decode(parsed.username)
    decoded_password = fully_decode(parsed.password)
    decoded_path = fully_decode(parsed.path)
    decoded_params = fully_decode(parsed.params)
    decoded_query = fully_decode(parsed.query)
    decoded_fragment = fully_decode(parsed.fragment)
    parts = [scheme,
             parsed.netloc,
             decoded_username,
             decoded_password,
             port_number,
             extracted.subdomain,
             extracted.domain,
             extracted.suffix,
             decoded_path,
             decoded_params,
             decoded_query,
             decoded_fragment
             ]
    return parts
def Shannon_entropy(data : str) -> float:
    if not data:
        return 0
    char_count = Counter(data)
    l = len(data)
    s = sum(c*log2(c) for c in char_count.values())
    return log2(l) - s/l
def has_part(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return 1
def part_length(parts : list, index : int) -> int:
    return len(parts[index])
def part_entropy(parts : list, index : int) -> float:
    return Shannon_entropy(parts[index])
def digit_ratio(data : str) -> float:
    if not data:
        return 0.0
    return sum(c.isdigit() for c in data) / len(data)
def dot_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '.')
def hyphen_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '-')
def hash_count(parts :  list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '#')
def percent_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '%')
def slash_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '/')
def at_sign_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '@')
def ampersand_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '&')
def equal_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '=')
def question_count(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return sum(1 for c in parts[index] if c == '?')


STRANGE_CHAR_PATTERN = re.compile(r'[^a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]')

def strange_char_count(data: list, index: int) -> int:
    if not data or index >= len(data):
        return 0
    part = data[index]
    if not part:
        return 0
    strange_chars = STRANGE_CHAR_PATTERN.findall(part)
    return len(strange_chars)
def is_ip(data : str) -> int:
    try:
        ipaddress.ip_address(data)
        return 1
    except ValueError:
        return 0
def load_and_preprocess_whitelist(file_whitelist : str) -> list:
    processed_list = []
    try:
        with open(file_whitelist, 'r', encoding = 'utf-8') as file:
            for line in file:
                check_domain = line.strip()
                if not check_domain:
                    continue
                extracted = extract_url(check_domain)
                host_domain = f"{extracted[DOMAIN]}.{extracted[SUFFIX]}"
                processed_list.append(host_domain)
    except FileNotFoundError:
        print("File not found")
    return list(set(processed_list))
def levenshtein(data : str, preprocessed_list : list) -> dict:
    threshold = max(1, floor(len(data) / 7))
    highest_score = 0
    most_similar_domain = ""
    data_len = len(data)
    for host_domain in preprocessed_list:
        len_diff = abs(data_len - len(host_domain))
        if len_diff > threshold:
            continue
        dist = Levenshtein.distance(data, host_domain, score_cutoff=threshold)
        if dist <= threshold:
            current_score = Levenshtein.normalized_similarity(data, host_domain)
            if current_score > highest_score:
                highest_score = current_score
                most_similar_domain = host_domain
    return {
        "normalized_similarity": highest_score,
        "domain": most_similar_domain
    }
def part_count(extracted : list) -> int:
    count = 0
    for part in url_structure:
        if extracted[part]:
            count += 1
    return count
def consonant_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    consonants = [c for c in letters if c not in VOWELS]
    return len(consonants) / len(letters)
def has_suspicious_keyword(data : str) -> int:
    if not data:
        return 0
    text_lower = data.lower()
    return 1 if any(kw in text_lower for kw in SUSPICIOUS_KEYWORDS) else 0
def char_repeated_ratio(data : str) -> float:
    if not data or len(data) < 2:
        return 0.0
    repeated = sum(
        1 for i in range(1, len(data))
        if data[i] == data[i-1]
    )
    return repeated / (len(data) - 1)
def max_consecutive_char(data : str) -> int:
    if not data:
        return 0
    max_consecutive = 1
    current_consecutive = 1
    for i in range(1, len(data)):
        if data[i] == data[i-1]:
            current_consecutive += 1
            max_consecutive = max(max_consecutive, current_consecutive)
        else:
            current_consecutive = 1
    return max_consecutive
#moi add 30/5
def _is_uuid_path(data: list) -> int:
    """Phát hiện path chứa UUID (dấu hiệu C2 server / malware callback).
    Ví dụ: /ba1019ee-a048-4bd5-a90d-1fc5da2b8696
    """
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return 1 if re.search(uuid_pattern, data[PATH].lower()) else 0
def is_shortened(data : list) -> int:
    if not data[DOMAIN] or not data[SUFFIX]:
        return 0
    host_domain = data[DOMAIN]+'.'+data[SUFFIX]
    if host_domain in SHORTENERS or data[DOMAIN] in SHORTENERS:
        return 1
    return 0
def has_download_param(data : list) -> int:
    if not data:
        return 0
    if len(data[PATH]) > 7 or len(data[QUERY]) > 7:
        if ('download' in data[QUERY].lower() or
            'download' in data[PATH].lower() or
            'install' in data[PATH].lower()):
            return 1
    return 0
def has_suspicious_port(data : list) -> int:
    if not data[PORT]:
        return 0
    if data[PORT] not in PORTS:
        return 1
    return 0
def is_free_hosting(data : list) -> int:
    if not data:
        return 0
    for h in FREE_HOSTING:
        if data[DOMAIN].endswith(h):
            return 1
    return 0
def free_hosting_download(data : list) -> int:
    if is_free_hosting(data) and has_download_param(data):
        return 1
    return 0
def has_unicode(data : list) -> int:
    if not data:
        return 0
    host_domain = data[DOMAIN]+'.'+data[SUFFIX]
    if any(ord(c) > 127 for c in host_domain):
        return 1
    return 0
def has_punycode(data : list) -> int:
    if not data:
        return 0
    host_domain = data[DOMAIN]+'.'+data[SUFFIX]
    if "xn--" in host_domain:
        return 1
    return 0
def suspicious_tld(data : list) -> int:
    if not data[SUFFIX]:
        return 0
    if data[SUFFIX] in SUSPICIOUS_TLDS:
        return 1
    return 0
def get_scheme(url : str) -> str:
    extracted = extract_url(url)
    if not extracted:
        return ''
    if extracted[SCHEME] == "https":
        return "https"
    elif extracted[SCHEME] == "http":
        return "http"
    elif extracted[SCHEME] == "ftp":
        return "ftp"
    elif extracted[SCHEME] == '':
        return ''
    else:
        return "other"
def features_extraction(url : str, whitelist : list) -> list:
    if not url:
        return []
    extracted = extract_url(url)
    host_domain = extracted[DOMAIN]+'.'+extracted[SUFFIX]
    #nhom 0: ten tung part
    scheme = extracted[SCHEME]
    netloc = extracted[NETLOC]
    path = extracted[PATH]
    query = extracted[QUERY]
    fragment = extracted[FRAGMENT]
    subdomain = extracted[SUBDOMAIN]
    domain = extracted[DOMAIN]

    #nhóm 1: part có tồn tại hay không
    number_of_part = part_count(extracted)
    has_scheme = has_part(extracted, SCHEME)
    has_netloc = has_part(extracted, NETLOC)
    has_path = has_part(extracted, PATH)
    has_params = has_part(extracted, PARAMS)
    has_query = has_part(extracted, QUERY)
    has_fragment = has_part(extracted, FRAGMENT)
    has_username = has_part(extracted, USERNAME)
    has_password = has_part(extracted, PASSWORD)
    has_port = has_part(extracted, PORT)
    has_subdomain = has_part(extracted, SUBDOMAIN)
    has_domain = has_part(extracted, DOMAIN)
    has_suffix = has_part(extracted, SUFFIX)

    #nhóm 2:parts length
    netloc_length = part_length(extracted, NETLOC)
    path_length = part_length(extracted, PATH)
    query_length = part_length(extracted, QUERY)
    fragment_length = part_length(extracted, FRAGMENT)
    subdomain_length = part_length(extracted, SUBDOMAIN)
    domain_length = part_length(extracted, DOMAIN)

    # nhom 3: entropy
    url_entropy = Shannon_entropy(url)
    netloc_entropy = part_entropy(extracted, NETLOC)
    path_entropy = part_entropy(extracted, PATH)
    query_entropy = part_entropy(extracted, QUERY)
    subdomain_entropy = part_entropy(extracted, SUBDOMAIN)
    domain_entropy = part_entropy(extracted, DOMAIN)

    #nhom 4: ky tu dac biet
    hyphen_in_subdomain = hyphen_count(extracted, SUBDOMAIN)
    hyphen_in_domain = hyphen_count(extracted, DOMAIN)
    unicode = has_unicode(extracted)
    punycode = has_punycode(extracted)
    at_sign_in_netloc = at_sign_count(extracted, NETLOC)
    slash_in_path = slash_count(extracted, PATH)
    dot_in_path = dot_count(extracted, PATH)
    strange_in_query = strange_char_count(extracted, QUERY)
    equal_in_query = equal_count(extracted, QUERY)
    ampersand_in_query = ampersand_count(extracted, QUERY)
    number_subdomain = dot_count(extracted, SUBDOMAIN)+1 if extracted[SUBDOMAIN] else 0


    #nhom 5: lexical/string
    normalized_levenshtein_domain = levenshtein(host_domain, whitelist).get("normalized_similarity")
    normalized_levenshtein_subdomain = levenshtein(extracted[SUBDOMAIN], whitelist).get("normalized_similarity")
    random_domain_check = consonant_ratio(extracted[DOMAIN])
    random_subdomain_check = consonant_ratio(extracted[SUBDOMAIN])
    number_ratio_domain = digit_ratio(extracted[DOMAIN])
    number_ratio_subdomain = digit_ratio(extracted[SUBDOMAIN])
    repeated_domain_check = char_repeated_ratio(extracted[DOMAIN])
    repeated_path_check = char_repeated_ratio(extracted[PATH])
    repeated_url_check = char_repeated_ratio(url)
    longest_repeated_chain = max_consecutive_char(url)
    ip_domain = is_ip(extracted[DOMAIN])
    suspicious_key_domain = has_suspicious_keyword(extracted[DOMAIN])
    suspicious_key_subdomain = has_suspicious_keyword((extracted[SUBDOMAIN]))
    suspicious_key_path = has_suspicious_keyword(extracted[PATH])
    suspicious_key_query = has_suspicious_keyword(extracted[QUERY])
    shortened = is_shortened(extracted)


    #nhom 6: nhom con lai
    has_uuid_path = _is_uuid_path(extracted)
    download_param = has_download_param(extracted)
    free_host = is_free_hosting(extracted)
    free_host_download = free_hosting_download(extracted)
    suspicious_suffix = suspicious_tld(extracted)

    features = [scheme, netloc, path, query, fragment, subdomain, domain,
                number_of_part, has_scheme, has_netloc, has_path, has_params, has_query, has_fragment,
                has_username, has_password, has_port, has_subdomain, has_domain, has_suffix,
                netloc_length, path_length, query_length, fragment_length, subdomain_length, domain_length,
                url_entropy, netloc_entropy, path_entropy, query_entropy, subdomain_entropy, domain_entropy,
                hyphen_in_subdomain, hyphen_in_domain, unicode, punycode, at_sign_in_netloc,
                slash_in_path, dot_in_path, strange_in_query, equal_in_query, ampersand_in_query, number_subdomain,
                normalized_levenshtein_domain, normalized_levenshtein_subdomain, random_domain_check, random_subdomain_check,
                number_ratio_domain, number_ratio_subdomain, repeated_domain_check, repeated_path_check, repeated_url_check,
                longest_repeated_chain, ip_domain, suspicious_key_domain, suspicious_key_subdomain, suspicious_key_path,
                suspicious_key_query, shortened, has_uuid_path, download_param, free_host,free_host_download, suspicious_suffix]

    return features


