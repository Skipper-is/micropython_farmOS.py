

class farmOS:

    def __init__(self, hostname, username, password):
        self.APISession = APISession(hostname, username, password)


class APISession:

    def __init__(self, hostname, username, password):
        # Initial setup of the APISession takes the hostname (including the http/https:// )
        self.username = username
        self.password = password
        if hostname[-1] == "/":
            self.hostname = hostname[:-1]
        else:
            self.hostname = hostname
        self.token = None
        self.authenticated = False

    def authenticate(self):
        # Send a request to the server
        # This is using the farmOS user logon form to get a cookie from the server
        # It will send the username and password to the hostname/user/login you have provided
        header = {"Content-Type": "application/x-www-form-urlencoded"}  # Set the header to form-urlencoded, so we can send the form login data

        logindetails = {"name": self.username,
                    "pass": self.password,
                    "form_id": "user_login"}  # The actual login data
        options = ""  # Placeholder for the actual login options

        for k in logindetails:
            options += k + "=" + logindetails[k] + "&"  # For each of the pieces of login data, we'll put a = between the form id, and the data
            # So "name"="Bob"& then we're on to the next one

        self.request = self.http_request("/user/login", method="POST", options=options, headers=header)  # Send the actual HTTP request
        # We're going through the APISession version of request, as it will append the hostname to the request. You could always roll your own by calling
        # micropython-farmOS.request()

        if self.request.status_code == 302:  # Drupal redirects the user once login is successful, if that is true, we've come to the right place

            if self.request.cookie:  # If we have an actual cookie
                self.cookie = self.request.cookie  # Let us save that cookie to the APISession instance, so we can use it again
                # here we are sending the cookie we just got to the restws/session/token API, to get an OAuth2 token.
                self.request = self.http_request("/restws/session/token", cookies=self.cookie)

                if self.request.status_code == 200:  # Success!
                    self.token = self.request.text  # Now we store the token that was sent back

                    self.authenticated = True  # And store authenticated as true, so we know we've got a token saved

        if self.request.status_code == 200:  # If the login page doesn't send 302, it means you've typed in your username or password wrong
            print("Error, password or username incorrect")  # So we're going to print a warning for that

        if self.request.status_code == 404:  # If you get a 404, then your hostname is probably incorrect.
            print("Hostname may be incorrect, login page not found")
        # If this is false, we have not got the correct login. We may need to try again.
        return self.authenticated

    def http_request(self, urlreq, method="GET", options=None, headers={}, json=None, cookies=None):
        requestedURL = self.hostname + urlreq
        print(requestedURL)
        print(cookies)
        r = request(method, url=requestedURL, data=options, json=json, headers=headers, cookies=cookies)
        return r


class Requests:
    # This is a port/rewrite of urequests - from MicroPython-lib
    # I have added return of cookies to the function
    def __init__(self, f):
        self.raw = f
        self.encoding = "utf-8"
        self._cached = None

    def close(self):
        if self.raw:
            self.raw.close()
            self.raw = None
        self._cached = None

    @property
    def content(self):
        if self._cached is None:
            try:
                self._cached = self.raw.read()
            finally:
                self.raw.close()
                self.raw = None
        return self._cached

    @property
    def text(self):
        return str(self.content, self.encoding)

    def json(self):
        import ujson
        return ujson.loads(self.content)


def request(method, url, data=None, json=None, headers={}, cookies=None, OAuthToken=None, stream=None):
    import usocket
    print(cookies)
    print(method)
    cookie = None
    try:
        proto, dummy, host, path = url.split("/", 3)
    except ValueError:
        proto, dummy, host = url.split("/", 2)
        path = ""
    if proto == "http:":
        port = 80
    elif proto == "https:":
        import ussl
        port = 443
    else:
        raise ValueError("Unsupported protocol: " + proto)

    if ":" in host:
        host, port = host.split(":", 1)
        port = int(port)

    ai = usocket.getaddrinfo(host, port, 0, usocket.SOCK_STREAM)
    ai = ai[0]

    s = usocket.socket(ai[0], ai[1], ai[2])
    try:
        s.connect(ai[-1])
        if proto == "https:":
            s = ussl.wrap_socket(s, server_hostname=host)
        s.write(b"%s /%s HTTP/1.0\r\n" % (method, path))
        if "Host" not in headers:
            s.write(b"Host: %s\r\n" % host)
        # Iterate over keys to avoid tuple alloc
        for k in headers:
            print(k)
            print(headers[k])
            s.write(k)
            s.write(b": ")
            s.write(headers[k])
            s.write(b"\r\n")
        if json is not None:
            assert data is None
            import ujson
            data = ujson.dumps(json)
            s.write(b"Content-Type: application/json\r\n")
        if data:
            s.write(b"Content-Type: text/plain\r\n")
            s.write(b"Content-Length: %d\r\n" % len(data))
        if cookies:
            cookieString = b"Cookie: %s\r\n" % (cookies)
            print(cookieString)
            s.write(cookieString)
            if OAuthToken:
                token = (b"Authorization: Bearer %s\r\n" % (OAuthToken))
                s.write(token)
        s.write(b"\r\n")
        if data:
            s.write(data)

        l = s.readline()
        print(l)
        l = l.split(None, 2)
        status = int(l[1])
        reason = ""
        if len(l) > 2:
            reason = l[2].rstrip()
        while True:
            l = s.readline()
            if not l or l == b"\r\n":
                break
            print(l)
            if l.startswith(b'Set-Cookie') and status not in [401, 403]:
                cookieStr = l.decode('utf-8')
                cookie = cookieStr.split("; expires")[0][12:]
                print("Cookie\r\n")
                print(cookie)
            if l.startswith(b"Transfer-Encoding:"):
                if b"chunked" in l:
                    raise ValueError("Unsupported " + l)
    except OSError:
        s.close()
        raise

    resp = Requests(s)
    resp.status_code = status
    resp.reason = reason
    resp.cookie = cookie
    print(resp.cookie)
    return resp


def head(url, **kw):
    return request("HEAD", url, **kw)


def get(url, **kw):
    return request("GET", url, **kw)


def post(url, **kw):
    return request("POST", url, **kw)


def put(url, **kw):
    return request("PUT", url, **kw)


def patch(url, **kw):
    return request("PATCH", url, **kw)


def delete(url, **kw):
    return request("DELETE", url, **kw)
