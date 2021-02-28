#!/usr/bin/python
r"""
Taken from https://github.com/plone/plone.session/blob/master/plone/session/tktauth.py
The main difference is in how the "ip" is encoded in createTicket()
"""

from struct import pack

import hashlib
import hmac
import six
import time
import sys


def safe_encode(value, encoding='utf-8'):
    """Convert unicode to the specified encoding.

    copied from Products.CMFPlone.utils b/c this package does not depend on it
    """
    if isinstance(value, six.text_type):
        value = value.encode(encoding)
    return value

def mod_auth_tkt_digest(secret, data1, data2):
    # data1: addr + timestamp
    # data2: userid+token_list+user_data
    digest0 = hashlib.md5(data1 + secret + data2).hexdigest()
    if not six.PY2:
        # In Python 3 hashlib.md5(value).hexdigest() wants a bites value
        # and returns text
        digest0 = digest0.encode()
    digest = hashlib.md5(digest0 + secret).hexdigest()
    return digest

def createTicket(secret, userid, tokens=(), user_data='', ip='0.0.0.0',
                 timestamp=None, encoding='utf-8', mod_auth_tkt=False):
    """
    By default, use a more compatible
    """
    if timestamp is None:
        timestamp = int(time.time())
    secret = safe_encode(secret)
    userid = safe_encode(userid)
    tokens = [safe_encode(t) for t in tokens]
    user_data = safe_encode(user_data)

    token_list = b','.join(tokens)

    # ip address is part of the format, set it to 0.0.0.0 to be ignored.
    # pack is used to convert timestamp from an unsigned integer to 4 bytes
    # in network byte order.
    # Unfortunately, some older versions of Python assume that longs are always
    # 32 bits, so we need to trucate the result in case we are on a 64-bit
    # naive system.
    ##data1 = inet_aton(ip)[:4] + pack('!I', timestamp) # THIS is the line that was modified to work with lighttpd mod_authn_tkt
    data1 = ip + pack('!I', timestamp)
    data2 = b'\0'.join((userid, token_list, user_data))
    if mod_auth_tkt:
        digest = mod_auth_tkt_digest(secret, data1, data2)
    else:
        # a sha256 digest is the same length as an md5 hexdigest
        digest = hmac.new(secret, data1 + data2, hashlib.sha256).digest()

    if not isinstance(digest, six.binary_type):
        digest = digest.encode()

    # digest + timestamp as an eight character hexadecimal + userid + !
    ticket = b'%s%08x%s!' % (digest, timestamp, userid)
    if tokens:
        ticket += token_list + b'!'
    ticket += user_data

    return ticket

if __name__ == '__main__':
    SECRET = 'abcdefghijklmnopqrstuvwxyz0123456789'
    userid = 'UserID'
    timestamp = 1216720800
    tokens = ("token")
    user_data = "HOLA!"
    tkt = createTicket(SECRET, userid, tokens=tokens, user_data=user_data, ip="192.168.33.1", timestamp=timestamp, mod_auth_tkt=True)
    from six.moves import http_cookies
    import binascii
    cookie = http_cookies.SimpleCookie()
    cookie['auth_tkt'] = binascii.b2a_base64(tkt).strip().decode()

    sys.stdout.write("Status: 200 OK\r\n");
    sys.stdout.write("Content-type: text/html\r\n");
    sys.stdout.write("%s\r\n\r\n" % (cookie));

    print("<!doctype html>");
    print("<html lang=\"en\">");
    print("<head>");
    print("<meta charset=\"utf-8\">");
    print("<title>My Auto Login CGI</title>");
    print("</head>");
    print("<body>");
    print("<p>Yeah, you have been logged in, try accessing the <a href=\"/protected.html\">Secrets</a> now<p>");
    print("<p>This CGI should check username and password in whichever way and then generate the cookie, but for this example it automatically lets you in<p>");
    print("<p>The auth_tkt Cookie should look like: %s<p>" % (cookie['auth_tkt']));
    print("<p>Press F12 to check it out in the dev tools of your browser<p>");
    print("<p>If you modify or delete it, you'd be logged off<p>");
    print("</body>");
