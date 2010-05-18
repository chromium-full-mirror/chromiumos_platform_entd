#!/usr/bin/python
# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from BaseHTTPServer import HTTPServer
from OpenSSL import SSL
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import BaseServer

import base64
import cgi
import re
import socket

CERT_ID='12345'
CSR_REPLY = """
<html>
  <head></head>
  <body>
    Lots of text that might appear in a valid CSR response, including
    a <a href="issue?foo=bar&ReqId=%s&yippy">link</a>
    to where you might go to get your actual cert.
  </body>
</html>
""" % CERT_ID

#
# The SSL related code in this file was partially copied from:
# http://code.activestate.com/recipes/496786-simple-xml-rpc-server-over-https/
# which is covered by the PSF licensce: http://www.python.org/psf/license/
#

class HTTPSecureServer(HTTPServer):
  def __init__(self, server_address, HandlerClass):
    BaseServer.__init__(self, server_address, HandlerClass)
    ctx = SSL.Context(SSL.SSLv3_METHOD)
    # TODO(rginda): Add command line options for these.
    ctx.use_privatekey_file('server.key')
    ctx.use_certificate_file('server.crt')
    self.socket = SSL.Connection(ctx, socket.socket(self.address_family,
                                                    self.socket_type))
    self.server_bind()
    self.server_activate()

class Handler(SimpleHTTPRequestHandler):
  """Mock out a simple CSR server."""

  def setup(self):
    self.connection = self.request
    self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
    self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)


  def check_auth(self):
    authz = self.headers.get('Authorization')
    if not authz:
      return False

    m = re.search(r'Basic (\S+)', authz)
    if not m:
      return False

    try:
      authz = base64.b64decode(m.group(1))
    except TypeError:
      return False

    (username, password) = authz.split(':')
    if password != username + '_password':
      return False

    return True


  def do_POST(self):
    self.do_something()


  def do_GET(self):
    self.do_something()


  def do_something(self):
    if not self.check_auth():
      self.send_response(401)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('WWW-Authenticate', 'Basic realm="Mock Cert Server"')
      self.end_headers()
      return

    # Capture the path and optional query string.
    m = re.search(r'/([^\?]+)(?:\?(.*))?', self.path)
    if not m:
      # Regexp failed somehow, 404 NOT_FOUND
      self.send_response(404)
      return

    if m.group(1) == 'csr':
      self.handle_CSR(m.group(2))
    elif m.group(1) == 'issue':
      self.handle_issue(m.group(2))
    else:
      self.send_response(404)


  def handle_CSR(self, query_string):
    """Handle a mock "Certificate Signing Request" request.

    Checks that the client performed an HTTP POST containing the form variables
    ("CertRequest", "CertAttribute", "email", "SAN").  Does not check
    the values of these variables.  The POST may be url-encoded or a
    multiplart form.

    Replys with an HTML document with an embedded link to where you might get
    the actual certificate.
    """
    if self.command != 'POST':
      self.send_response(405)
      return

    # This post should have some data in the request entity.  The
    # Content-Type header say how it was encoded, and possibly some
    # metadata (part boundry) to help parse it.
    ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
    length = int(self.headers.getheader('Content-Length'))

    if ctype == 'multipart/form-data':
      form = cgi.parse_multipart(self.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
      qs = self.rfile.read(length)
      form = cgi.parse_qs(qs, keep_blank_values=1)
    else:
      self.send_response(415)
      return

    # Ensure that a few variables are present, just to sanity check that the
    # client was able to form a proper POST.
    missing_vars = []
    for name in ("CertRequest", "CertAttribute", "email", "SAN"):
      if name not in form:
        missing_vars.append(name)

    if missing_vars:
      self.simple_response("Missing: %s" % missing_vars)

    # We're not actually going to be processing the CSR, just return a document
    # that makes it look like we did.
    self.simple_response(CSR_REPLY)


  def handle_issue(self, query_string):
    """Handle a mock "Certificate Issue Request" (or whatever it might be
    officially called.)

    Checks that the client performed an HTTP GET with an "id=<CERT_ID>" where
    CERT_ID is the identifier given out during the CSR.

    Replys with a text/plain document that a caller might assume was a
    certificate (even though it's just the string 'certificate: <CERT_ID>').
    """
    if not query_string:
      self.simple_response("Missing query string", "text/plain")

    form = cgi.parse_qs(query_string, keep_blank_values=1)
    if 'id' not in form:
      self.simple_response("Missing parameter: id", "text/plain")
      return

    id = form['id'][0]

    if id != CERT_ID:
      self.simple_response("Unknown id: %s" % id, "text/plain")
    else:
      self.simple_response("certificite: %s" % id, "text/plain")


  def simple_response(self, msg, type="text/html"):
    """Send a simple HTTP response.

    Sends the response line, headers, and the message provided.
    """
    self.send_response(200)
    self.send_header("Content-Type", type)
    self.end_headers()
    self.wfile.write(msg + "\n")


if __name__ == '__main__':
  ip = '127.0.0.1'
  port = 4343
  print "Mock certificate server starting..."
  httpd = HTTPSecureServer((ip, port), Handler)
  sa = httpd.socket.getsockname()
  print "Serving HTTPS on %s:%s." % (sa[0], sa[1])
  httpd.serve_forever()
