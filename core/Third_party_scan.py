from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen, Request
import itertools
import sys
import time
from bs4 import BeautifulSoup


def scan(i_url):
    url = "https://sitecheck.sucuri.net/results/{}".format(i_url)

    def waiting(scanning_thread):
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if scanning_thread.done():
                return
            sys.stdout.write('\033[93m\rWaiting third-party scanning [{}]\033[0m'.format(c))
            sys.stdout.flush()
            time.sleep(0.1)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(urlopen, Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0'}))
        waiting(future)
        u = future.result().read()

    soup = BeautifulSoup(u, "html.parser")

    print("\nscan by https://sitecheck.sucuri.net")
    if soup.find("div", {"class": "red-warn"}):
        print("\033[91m")
        print(soup.find_all("td", {"class": "red"})[1].get_text())
        print("\033[0m")
        if soup.find("table", {"class": "table infected-table-main"}):
            s = (soup.find("table", {"class": "table infected-table-main"})).tbody.find_all("tr")
            print("ISSUE\t==>\tURL\033[91m")
            for n in s:
                t = n.find_all("td")
                print("{}\t{}".format(t[0].get_text(), t[2].get_text().split()[0]))
            print("\033[0m")
            z = soup.find_all("table", {"class": "table scan-findings"})[1].tbody.find_all("tr")
            for n in z:
                print(n.get_text())
            print("\033[94mSee more:\033[0m https://sitecheck.sucuri.net/results/{}".format(i_url))
            return
        else:
            z = soup.find_all("table", {"class": "table scan-findings"})[1].tbody.find_all("tr")
            for n in z:
                print(n.get_text())
            print("\033[94mSee more:\033[0m https://sitecheck.sucuri.net/results/{}".format(i_url))
            return
    print("")
    try:
        result = soup.find_all("tr")[4:8]
        for l in result:
            n = l.get_text().strip().split("\n")
            print("{} - \033[92m{}\033[0m".format(n[0], n[1]))
        print("")
        print("\033[93m{}\033[0m".format(soup.find_all("td", {"class": "blue"})[1].get_text()))
        result = soup.find_all("tr")[9:19]
        for l in result:
            print(l.get_text())
    except:
        print("There are some problems, see more https://sitecheck.sucuri.net/results/{}".format(i_url))
    print("")
