

class farmOS:

    def __init__(self, hostname, username, password):
        self.session = APISession(hostname, username, password)
        self.log = LogAPI(self.session)
        self.asset = AssetAPI(self.session)
        self.area = AreaAPI(self.session)
        self.term = TermAPI(self.session)

    def authenticate(self):
        if (self.session.authenticate()):
            print('Success! Cookie and Authentication Token have been collected!')
        return True

    def info(self):
        response = self.session.http_request(path='farm.json')
        if (response.status_code == 200):
            return response.json()
        return []

    def vocabulary(self, machine_name=None):
        path = 'taxonomy_vocabulary.json'
        params = {}
        params['machine_name'] = machine_name

        response = self.session.http_request(path=path, params=params)

        if (response.status_code == 200):
            data = response.json()
            if 'list' in data:
                return data['list']
        return []


class APISession:

    def __init__(self, hostname, username, password, *args, **kwargs):
        super(APISession, self).__init__(*args, **kwargs)
        # Initial setup of the APISession takes the hostname (including the http/https:// )
        self.username = username
        self.password = password
        if hostname[-1] == '/':
            self.hostname = hostname[:-1]
        else:
            self.hostname = hostname
        self.token = None
        self.cookie = None
        self.authenticated = False

    def authenticate(self):
        # Send a request to the server
        # This is using the farmOS user logon form to get a cookie from the server
        # It will send the username and password to the hostname/user/login you have provided
        header = {'Content-Type': 'application/x-www-form-urlencoded'}  # Set the header to form-urlencoded, so we can send the form login data

        logindetails = {'name': self.username,
                    'pass': self.password,
                    'form_id': 'user_login'}  # The actual login data
        options = ''  # Placeholder for the actual login options

        for k in logindetails:
            options += k + '=' + logindetails[k] + '&'  # For each of the pieces of login data, we'll put a = between the form id, and the data
            # So 'name'='Bob'& then we're on to the next one

        self.request = self.http_request('/user/login', method='POST', options=options, headers=header)  # Send the actual HTTP request
        # We're going through the APISession version of request, as it will append the hostname to the request. You could always roll your own by calling
        # micropython-farmOS.request()
        if self.request.status_code == 200:  # If the login page doesn't send 302, it means you've typed in your username or password wrong
            print('Error, password or username incorrect')  # So we're going to print a warning for that

        if self.request.status_code == 404:  # If you get a 404, then your hostname is probably incorrect.
            print('Hostname may be incorrect, login page not found')

        if self.request.status_code == 302:  # Drupal redirects the user once login is successful, if that is true, we've come to the right place

            if self.request.cookie:  # If we have an actual cookie
                self.cookie = self.request.cookie  # Let us save that cookie to the APISession instance, so we can use it again
                # here we are sending the cookie we just got to the restws/session/token API, to get an token.
                self.request = self.http_request('/restws/session/token', cookies=self.cookie)

                if self.request.status_code == 200:  # Success!
                    self.token = self.request.text  # Now we store the token that was sent back

                    self.authenticated = True  # And store authenticated as true, so we know we've got a token saved

        # If this is false, we have not got the correct login. We may need to try again.
        return self.authenticated

    def http_request(self, path, method='GET', options=None, headers={}, json=None, cookies=None, params={}):
        # If you don't add the first / to the request url, like 'farm_asset.json?type=animal'
        # the function will fail, so we just check, and add a / if needed
        if (path[0] != '/'):
            path = '/' + path
        requestedURL = self.hostname + path

        if self.cookie and (cookies is None):  # Check if cookies have been stored yet
            cookies = self.cookie  # And add them to the request
        if self.authenticated and self.token:  # And see if we have a token
            headers['Authorization'] = 'Bearer ' + self.token  # And add the token to the request as well
        r = request(method, url=requestedURL, data=options, json=json, headers=headers, cookies=cookies, params=params)
        return r


class BaseAPI():

    def __init(self, session, entity_type=None):
        self.session = session
        self.entity_type = entity_type
        self.filters = {}

    def getRecordByID(self, id):
        ''' Takes the ID of the record, and returns the data '''
        path = self.entity_type + '/' + str(id) + '.json'
        # TODO remove .json and add in filter for Accept: application.json or wait for the fix to the entity.controller
        response = self.session.http_request(path)

        if (response.status_code == 200):  # If we get a success - Return the JSON of the results
            return response.json()

        return []  # Or return an empty list

    def getRecordData(self, filters):
        path = self.entity_type + '.json'

        filters = {**self.filtes, **filters}

        response = self.session.http_request(path, params=filters)

        data = {}

        if (response.status_code == 200):
            response = response.json()
            if 'list' in response:
                data['list'] = response['list']
                pageURL = {}
                pageURL['self'] = response['self']
                pageURL['first'] = response['first']
                pageURL['last'] = response['last']
                pageNumbers = {}
                pageNumbers = extractPageNumbers(pageURL)

                data['page'] = pageNumbers

        return data

    def getAllRecordData(self, filters, page=0, list=None):
        # This function will cycle through calling getRecordData until it reaches the last page of data. Useful if you've got more than 1 page of data (100+)
        if list is None:
            list = []
        filters['page'] = page  # The next request will look for page #x, initially 0, then iterating through

        response = self.getRecordData(filter=filters)  # Get the x page of data

        if ('list' in response):
            list = list + response['list']  # Append the new list of data onto the original one

        # Are there multiple pages of data from te request?
        if ('page' in response):
            last_page = response['page']['last']

            if (last_page == page):
                data = {
                    'page': {
                        'first': response['page']['first'],
                        'last': response['page']['last']
                        },
                    'list': list
                    }

                return data
        else:
            return self.getAllRecordData(list=list, page=(page+1), filters=filters)

    def getRecords(self, filters=None):

        if filters is None:
            filters = {}

        if isinstance(filters, (int, str)):
            return self.getRecordByID(filters)

        elif isinstance(filters, dict):
            if 'page' in filters:
                return self.getRecordData(filters=filters)
            else:
                return self.getAllRecordData(filters=filters)

    def get(self, filters=None):

        data = self.getRecords(filters=filters)

        return data

    def send(self, payload):
        options = {}
        options['json'] = payload

        id = payload.pop['id', None]
        if id:
            path = self.entity_type + '/' + str(id)
            response = self.session.http_request(method="PUT", path=path, options=options)
        else:
            path = self.entity_type
            response = self.session.http_request(method="POST", path=path, options=options)
        if (response.status_code == 201):
            return response.json()
        if (response.status_code == 200):
            entity_data = {
                'id': id,
                'url': path,
                'resource': self.entity_type,
                }
            return entity_data


class LogAPI(BaseAPI):

    def __init__(self, session):

        super().__init(session=session, entity_type='log')


class AssetAPI(BaseAPI):

    def __init__(self, session):

        super().__init(session=session, entity_type='farm_asset')


class TermAPI(BaseAPI):

    def __init(self, session):
        super().__init(session=session, entity_type='taxonomy_term')

    def get(self, filters=None):

        if isinstance(filters, str):
            self.filters['bundle'] = filters
            filters = {}

        data = self.getRecords(filters=filters)

        return data


class AreaAPI(TermAPI):

    def __init__(self, session):
        super().__init__(session=session)
        self.filters['bundle'] = 'farm_areas'

    def get(self, filters=None):
        if isinstance(filters, int) or isinstance(filters, str):
            tid = str(filters)
            # Add tid to filters object
            filters = {
                'tid': tid
            }
        data = self.getRecords(filters=filters)

        return data


class Requests:
    # This is a port/rewrite of urequests - from MicroPython-lib
    # I have added return of cookies to the function
    def __init__(self, f):
        self.raw = f
        self.encoding = 'utf-8'
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


def request(method='GET', url=None, data=None, json=None, headers={}, cookies=None, token=None, stream=None, params={}):

    if url is None:  # Check if they've provided a URL!
        print("No URL returned!")
        return None
    import usocket
    print(cookies)  # TODO Remove
    print(method)  # TODO Remove
    cookie = None
    try:
        proto, dummy, host, path = url.split('/', 3)  # Break the url into the protocol, host, and the path
    except ValueError:
        proto, dummy, host = url.split('/', 2)
        path = ''
    if proto == 'http:':
        port = 80  # Standard HTTP, all good in the hood
    elif proto == 'https:':
        import ussl
        port = 443  # HTTPS, needs a different port, and we need to use ussl to create a secure socket
    else:
        raise ValueError('Unsupported protocol: ' + proto)  # Don't use ftp....

    if ':' in host:  # For all you crazies who use another port....
        host, port = host.split(':', 1)
        port = int(port)

    ai = usocket.getaddrinfo(host, port, 0, usocket.SOCK_STREAM)  # Get the IP for the host
    ai = ai[0]

    s = usocket.socket(ai[0], ai[1], ai[2])  # Set up the socket
    for index, key in enumerate(params):
        if index == 0:
            if '?' not in path:
                # For the first key, we add ?
                path += '?'
            path += key + '=' + params[key] + '&'
    try:
        s.connect(ai[-1])
        if proto == 'https:':
            s = ussl.wrap_socket(s, server_hostname=host)  # If it i https, wrap that socket in an secure socket layer
        s.write(b'%s /%s HTTP/1.0\r\n' % (method, path))  # Posts something along the lines of: GET /farm_asset.json?type=animal HTTP/1.0
        if 'Host' not in headers:
            s.write(b'Host: %s\r\n' % host)
        # Iterate over keys to avoid tuple alloc
        for k in headers:
            print(k)  # TODO Remove
            print(headers[k])  # TODO Remove
            s.write(k)
            s.write(b': ')
            s.write(headers[k])
            s.write(b'\r\n')
        if json is not None:
            assert data is None
            import ujson
            data = ujson.dumps(json)
            s.write(b'Content-Type: application/json\r\n')  # If we have JSON, we need to put the content type header to json
        if data:

            s.write(b'Content-Length: %d\r\n' % len(data))
        if cookies:
            cookieString = b'Cookie: %s\r\n' % (cookies)
            print(cookieString)  # TODO Remove
            s.write(cookieString)
            if token:  # Only post the Token if we have the cookie, otherwise, it is a bit pointless
                token = (b'Authorization: Bearer %s\r\n' % (token))
                s.write(token)
        s.write(b'\r\n')
        if data:
            s.write(data)

        l = s.readline()
        print(l)  # TODO Remove
        l = l.split(None, 2)
        status = int(l[1])
        reason = ''
        if len(l) > 2:
            reason = l[2].rstrip()
        while True:
            l = s.readline()
            if not l or l == b'\r\n':
                break
            print(l)  # TODO Remove
            if l.startswith(b'Set-Cookie') and status not in [401, 403]:  # If we get a cookie under 'Unauthorised'...Not going to do much good
                cookieStr = l.decode('utf-8')
                cookie = cookieStr.split('; expires')[0][12:]
                print('Cookie\r\n')  # TODO Remove
                print(cookie)  # TODO Remove
            if l.startswith(b'Transfer-Encoding:'):
                if b'chunked' in l:
                    raise ValueError('Unsupported ' + l)
    except OSError:
        s.close()
        raise

    resp = Requests(s)
    resp.status_code = status
    resp.reason = reason
    resp.cookie = cookie
    return resp


def head(url, **kw):
    return request('HEAD', url, **kw)


def get(url, **kw):
    return request('GET', url, **kw)


def post(url, **kw):
    return request('POST', url, **kw)


def put(url, **kw):
    return request('PUT', url, **kw)


def patch(url, **kw):
    return request('PATCH', url, **kw)


def delete(url, **kw):
    return request('DELETE', url, **kw)


def extractPageNumbers(pageURL):
    if len(pageURL) == 3:
        if pageURL['first'] == pageURL['last']:  # If the first and last record are all the same, then there is only 1 page
            return [0, 0, 0]  # So we return 0, as it is page 0 for all of them
        else:  # Otherwise, we go through each one, get out the page number, and return that
            pageNumbers = {}
            for key in pageURL:
                page = pageURL[key]
                page = page.split('page=')[1]
                page = page.split('&')[0]
                if (page.isdigit()):  # This should always return true, unless I've dropped the ball somewhere
                    pageNumbers[key] = int(page)
                else:
                    pageNumbers[key] = 0
            return pageNumbers
