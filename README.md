# EllaScanner
Passive web scanner.

EllaScanner is a simple passive web scanner. Using this tool you can simply check your site’s security state.
```bash
./Start.py
Usage:
	./Start.py https:// or http://
```
Scanning of the site consists several phases: <br>
At the first phase, you can get recommendations related to http/https headers. <br>

The Second phase depends on information gather in the first phase, you can get CVEs related to server’s version. <br>

After this, the scanner uses sucuri.net and prints information about defaces, malicious codes, etc.<br>

And last but not least, if the site is Georgian you can get information from checknet.ge about site’s historical states.<br>

[see more](https://secrary.com/EllaScanner)

## Installation

```pip install -r requirements.txt```

./Start.py
