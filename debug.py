# debug.py
from src.feature import _subdomain_is_random, shannon_entropy

for host in ['kjvbjr.krokodilpince.hu', 'sagdxf.krokodilpince.hu']:
    sub = host.split('.')[0]
    vowels = sum(c in 'aeiou' for c in sub)
    vowel_ratio = vowels / len(sub)
    ent = shannon_entropy(sub)
    print(f'{sub}: vowel_ratio={vowel_ratio:.2f}, entropy={ent:.2f}, result={_subdomain_is_random(host)}')