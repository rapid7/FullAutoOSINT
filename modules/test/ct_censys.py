import requests
import re

def search(domain):
    base_url = "https://censys.io/ipv4/_search?q={}"
    url = base_url.format(domain)

    ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
    req = requests.get(url, headers={'User-Agent': ua})

    if req.ok:
        try:
            content = req.content.decode('utf-8')
            pattern = r'names on certificate"></i>([^<]*)<'
            regex = re.compile(pattern, re.IGNORECASE)
            data = []
            for match in regex.finditer(content):
                for i in match.group(1).split(","):
                    data.append(i.strip())
            return list(set(data))
        except Exception as err:
            print("Error retrieving information.")
            print err
    return None

for i in search("rapid7.com"):
    print i
