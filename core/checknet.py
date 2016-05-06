from bs4 import BeautifulSoup
import urllib.request
import urllib.parse


def ge(check_url):
    post_params = {
        "DomainAddress": "{}".format(check_url),
        "X-Requested-With": "XMLHttpRequest"
    }
    post_args = urllib.parse.urlencode(post_params).encode('utf-8')

    url = 'http://checknet.ge'

    fp = urllib.request.urlopen(urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0'}),
                                post_args).read()

    soup = BeautifulSoup(fp, "html.parser")

    if soup.find("span") and soup.find("span").get_text().encode(
            "utf-8") == b'\xe1\x83\xa9\xe1\x83\x90\xe1\x83\x9c\xe1\x83\x90\xe1\x83\xac\xe1\x83\x94\xe1\x83\xa0\xe1\x83\x98 \xe1\x83\x90\xe1\x83\xa0 \xe1\x83\x9b\xe1\x83\x9d\xe1\x83\x98\xe1\x83\xab\xe1\x83\x94\xe1\x83\x91\xe1\x83\x9c\xe1\x83\x90':
        print("\n\033[92mNothing found in history\033[0m")
    else:
        s = soup.find("div", {"class": "ipcxrili1"}).find_all("div")[9].get_text().split("\n")

        s = [x for x in s if x]
        checknet = ("Domain", "IP address", "URL", " Infection type", "Provider", "Incident date")
        if len(s)//6 > 3:
            print("\nFound \033[91m{}\033[0m security problems.\n\n\033[94mSee more:\033[0m http://checknet.ge\n\nLast three ones:".format(len(s)//6))
        for i, x in enumerate(s):
            if i // 6 == 3:
                return
            if i % 6 == 0:
                print("\n")
            if i % 6 == 3:
                print("{}: \033[91m{}\033[0m".format(checknet[i % 6], x))
            else:
                print("{}: {}".format(checknet[i % 6], x))
