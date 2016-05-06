import itertools
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.request import urlopen, Request


def cve_check(search_term):
    n_search_term = search_term.strip().split('+')[0].split()[0].replace("/", "%20")
    url = "https://web.nvd.nist.gov/view/vuln/search-results?query={}&search_type=all&cves=on".format(n_search_term)

    def waiting(scanning_thread):
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if scanning_thread.done():
                return
            sys.stdout.write('\033[93m\rPotential vulnerability searching {}  [{}]\033[0m'.format(search_term, c))
            sys.stdout.flush()
            time.sleep(0.1)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(urlopen, Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0'}))
        waiting(future)
        page = future.result().read()
    print("")
    soup = BeautifulSoup(page, "html.parser")
    vulnerabilities = dict()
    dt = soup.find_all("dt")
    dd = soup.find_all("dd")
    for (cve, summery) in zip(dt[5:], dd[6:]):
        vulnerabilities[cve.get_text().strip()] = "\n".join(summery.get_text().strip().split("\n")[:-1])
    if len(vulnerabilities) > 0:
        print("\033[91mPOTENTIAL vulnerabilities - {}:\033[0m".format(search_term))
        for i, (k, v) in enumerate(vulnerabilities.items()):
            print("\033[93m{}\033[0m - {}".format(k, v))
            if i == 5:
                print("\033[91mSee more:\033[0m",
                      "https://web.nvd.nist.gov/view/vuln/search-results?query={}&search_type=all&cves=on\n".format(
                              n_search_term))
                return
    print("\033[94mSee more:\033[0m",
          "https://web.nvd.nist.gov/view/vuln/search-results?query={}&search_type=all&cves=on\n".format(n_search_term))
