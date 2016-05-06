#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen, Request
import sys
import itertools
import time
import core.cve
import core.HttpHeaders
import core.Third_party_scan
import core.checknet


def main():
    if (len(sys.argv) == 1) or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print("Usage: \n\t{} https:// or http://".format(sys.argv[0]))
        sys.exit()
    url = sys.argv[1]
    if not url.startswith("http"):
        raise Exception("Invalid url")
    print('''
          ___           ___       ___       ___
         /  /\         /  /\     /  /\     /  /\\
        /  /::\       /  /:/    /  /:/    /  /::\\
       /  /:/\:\     /  /:/    /  /:/    /  /:/\:\\
      /  /::\ \:\   /  /:/    /  /:/    /  /::\ \:\\
     /__/:/\:\ \:\ /__/:/    /__/:/    /__/:/\:\_\:\\
     \  \:\ \:\_\/ \  \:\    \  \:\    \__\/  \:\/:/
      \  \:\ \:\    \  \:\    \  \:\        \__\::/
       \  \:\_\/     \  \:\    \  \:\       /  /:/ passive
        \  \:\        \  \:\    \  \:\     /__/:/ scanner
         \__\/         \__\/     \__\/     \__\/ v0.1

    ''')
    try:
        def waiting(scanning_thread):
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if scanning_thread.done():
                    return
                sys.stdout.write('\033[93m\r[{}]\033[0m'.format(c))
                sys.stdout.flush()
                time.sleep(0.1)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(urlopen, Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0'}))
            waiting(future)
            u = future.result()
    except:
        print("\n{} \033[91mis not accessible\033[0m".format(url))
        print('''
        Check the \033[93mhistory\033[0m of \033[93mGeorgian\033[0m web-pages and see what type of
        security problems were encountered at \033[93mdifferent time\033[0m''')

        if input("Continue (y/[n]) ") is "y":
            core.checknet.ge(url.strip("/").split("/")[-1:][0])
        sys.exit()

    http_headers = u.info()
    server = str(http_headers["Server"])
    x_powered = str(http_headers["X-Powered-By"])
    if input("Do you want to get recommendations related to http/https headers? (y/[n]) ") is "y":
        core.HttpHeaders.headers_check(url, http_headers)

    if len(server.strip().replace("/", " ").split()) > 1:
        if len(server.strip().replace("/", " ").split()[1].split(".")) > 1:
            core.cve.cve_check(http_headers["Server"])

    if len(x_powered.strip().replace("/", " ").split()) > 1:
        if len(x_powered.strip().replace("/", " ").split()[1].split(".")) > 1:
            core.cve.cve_check(http_headers["X-Powered-By"])

    core.Third_party_scan.scan(url)

    print('''
    Check the \033[93mhistory\033[0m of \033[93mGeorgian\033[0m web-pages and see what type of
    security problems were encountered at \033[93mdifferent time\033[0m''')

    if input("Continue (y/[n]) ") is "y":
        core.checknet.ge(url.strip("/").split("/")[-1:][0])  # http://site.ge/ ==> site.ge


if __name__ == '__main__':
    main()
