# micropython-farmOS.py
 A port/rewrite of FarmOS.py for the MicroPython platform
 
 TODO: Everything.
 - Every main function
 - Review cookie storage and expiry - Might need to set a timer to refetch the cookies and token on expiry, or I could just set it to fetch every day...
 
Currently using a rewrite of micropython-lib's urequests, that captures the cookies returned. 
