import re
def normalize_input_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url) and '/' not in url:
        url = 'https://' + url
    return url