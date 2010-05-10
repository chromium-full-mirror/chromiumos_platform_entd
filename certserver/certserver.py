#!/usr/bin/python
# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import BaseHTTPServer
import cgi
import re

CERT_ID=12345
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

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  """BaseHTTPRequestHandler subclass to mock out a simple CSR server."""


  def do_POST(self):
    self.do_something()


  def do_GET(self):
    self.do_something()


  def do_something(self):
    # Capture the path and optional query string.
    m = re.search(r'/([^\?]+)(\?.*)?', self.path)
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
    form = cgi.parse_qs(query_string, keep_blank_values=1)
    if 'id' not in form:
      self.simple_response("Missing: id")
    else:
      self.simple_response("certificite: %s" % form['id'], "text/plain")


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
  port = 8080
  print "Mock certificate server starting up on %s:%s" % (ip, port)
  httpd = BaseHTTPServer.HTTPServer((ip, port), Handler)
  httpd.serve_forever()
