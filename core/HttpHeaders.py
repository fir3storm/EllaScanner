def headers_check(url, http_headers):
    # https://www.owasp.org/index.php/List_of_useful_HTTP_headers
    print("\n\033[93mUseful/Missing HTTP headers:\033[0m")
    print(
        "These headers can be set in web server configuration (Apache, IIS, nginx), without changing actual application's code. This offers significantly faster and cheaper method for at least partial mitigation of existing issues, and an additional layer of defense for new applications.\n"
        "https://www.owasp.org/index.php/List_of_useful_HTTP_headers\n<")
    if not http_headers["Public-Key-Pins"] and not str(url).startswith("http://"):
        print(
            "\033[94mPublic-Key-Pins\033[0m - The Public Key Pinning Extension for HTTP (HPKP) is a security header that tells a web client to associate a specific cryptographic public key with a certain web server to prevent MITM attacks with forged certificates.")
    if not http_headers["Strict-Transport-Security"] and not str(url).startswith("http://"):
        print(
            "\033[94mStrict-Transport-Security\033[0m - HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) connections to the server. This reduces impact of bugs in web applications leaking session data through cookies and external links and defends against Man-in-the-middle attacks. HSTS also disables the ability for user's to ignore SSL negotiation warnings.")
    if not http_headers["X-Frame-Options"]:
        print(
            "\033[94mX-Frame-Options\033[0m - Provides Clickjacking protection. Values: deny - no rendering within a frame, sameorigin - no rendering if origin mismatch, allow-from: DOMAIN - allow rendering if framed by frame loaded from DOMAIN")
    if not http_headers["X-XSS-Protection"]:
        print(
            "\033[94mX-XSS-Protection\033[0m - This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.")
    if not http_headers["X-Content-Type-Options"]:
        print(
            "\033[94mX-Content-Type-Options\033[0m - The only defined value, \"nosniff\", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.")
    if not http_headers["Content-Security-Policy"]:
        print(
            "\033[94mContent-Security-Policy\033[0m - Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.")
    if not http_headers["Content-Security-Policy-Report-Only"]:
        print(
            "\033[94mContent-Security-Policy-Report-Only\033[0m - Like Content-Security-Policy, but only reports. Useful during implementation, tuning and testing efforts.")
    print("/>\n")

    # https://securityheaders.io
    print("\033[93mAdditional Information:\033[0m\n<")
    if http_headers["Server"] and len(http_headers["Server"].strip().replace("/", " ").split()) > 1:
        print("\033[94mServer\033[0m: {} - You should remove/change this value.".format(http_headers["Server"]))
    if http_headers["X-Powered-By"]:
        print(
            "\033[94mX-Powered-By\033[0m: {} - Trying to minimise the amount of information you give out about your server is a good idea. This header should be removed or the value changed.".format(
                http_headers["X-Powered-By"]))
    if str(url).startswith("http://") and http_headers["strict-transport-security"]:
        print(
            "\033[94mHTTP Strict Transport Security\033[0m is an excellent feature to support on your site and strengthens your implementation of TLS. That said, the HSTS header should not be returned over a HTTP connection, only HTTPS.")
    if str(url).startswith("http://") and http_headers["public-key-pins"]:
        print(
            "\033[94mpublic-key-pins\033[0m protects your site from MiTM attacks using rogue X.509 certificates. However, you should not return the HPKP header over a HTTP connection, only HTTPS.")
    print("/>\n")
