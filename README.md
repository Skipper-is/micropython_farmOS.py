# Micropython_farmOS.py
A port/rewrite of [FarmOS.py](https://github.com/farmOS/farmOS.py) for MicroPython.
## Features
Currently

 - Bearer Authenticaton
 - Get single logs by ID
 - Rewritten urequests
 - Send custom farmOS requests/posts
 - Yea, not a lot at the moment...

Loads more planned.......

## Setup
I have tried to keep this as a single file project, so uploading it to a MicroPython board should be pretty straightforward.
Copy the micropython_farmOS.py file to the MicroPython board (Tested on ESP32)
Import the library:

    import micropython_farmOS

Set up your variables:

    hostaddress = "http://YourFarmOSInstall.com/"
    username = "YourFarmOSLogin"
    password = "YourFarmOSPassword"

Initialise the module using:

    farm = micropython_farmOS.farmOS(hostname, username, password)

In order to use the module, you will need to get an Bearer token and  C🍪okie

    farm.authenticate()  # Returns true if it has been succesful

The cookie will expire after a couple of weeks, so if you're planning on running this long term, you'll need to set an alarm to call it again

### http_request
http_request is part of the FarmOS class, and can be used for sending your own custom requests to your FarmOS website
If you have run `farm.authenticate()`you can call it through

    farm.session.http_request()
The parameters available are:

    http_request(path, method="GET", options, headers={},json, cookies, params={})
You could get the `/farm.json` endpoint like this:

    farm = micropython_farmOS.farmOS(host, user, password)
    farm.authenticate()
    farmJSON = farm.session.http_request("/farm.json")
If you have authenticated, token and cookies are sent automatically
You can also use any of the other methods in [FarmOS.org/development/api/](https://farmos.org/development/api/)

### Logs
Currently the only thing that is really set up is getting logs by ID

    log = farm.log.getRecordByID(id)  # Where id is the ID of the log


## requests api
I have built in a version of the urequests module from micropython-lib. This version takes more arguments than the original:

    request = micropython_farmOS.request(method, url, data, json, headers, cookies, OAuthToken, stream, params)

You can also send get, post, put, patch and delete requests using:

    request = micropython_farmOS.get()
    request = micropython_farmOS.post()
    request = micropython_farmOS.put()
    request = micropython_farmOS.patch()
    request = micropython_farmOS.delete()

And the only essential parameters are url

request returns a Requests object with the following variables:

    request.status_code  # The status code of the response, eg 200 (OK)
    request.encoding  # The encoding of the response, default utf-8
    request.content()  # The reply, irrespective of encoding
    request.text()  # The reply, as a string (encoded with request.encoding)
    request.json()  # The reply, decoded by ujson
    request.cookie  # The cookie from the request - can be stored and sent along with the OAuth2 token

I did add in a base64 encoder for Basic Authorization, but removed it as you can add your own...
