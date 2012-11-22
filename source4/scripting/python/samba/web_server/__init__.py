# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright © Jelmer Vernooij <jelmer@samba.org> 2008
#
# Implementation of SWAT that uses WSGI
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

def render_placeholder(environ, start_response):
    """Send the user a simple placeholder about missing SWAT."""
    status = '200 OK'
    response_headers = [('Content-type', 'text/html')]
    start_response(status, response_headers)

    yield "<!doctype html>\n"
    yield "<html>\n"
    yield "  <title>The Samba web service</title>\n"
    yield "</html>\n"

    yield "<body>\n"
    yield "<p>Welcome to this Samba web server.</p>\n"
    yield "<p>This page is a simple placeholder. You probably want to install "
    yield "SWAT. More information can be found "
    yield "<a href='http://wiki.samba.org/index.php/SWAT2'>on the wiki</a>.</p>"
    yield "</p>\n"
    yield "</body>\n"
    yield "</html>\n"


def __call__(environ, start_response):
    """Handle a HTTP request."""
    from wsgiref.util import application_uri, shift_path_info
    from urlparse import urljoin

    try:
        import swat
    except ImportError, e:
        print "NO SWAT: %r" % e
        have_swat = False
    else:
        have_swat = True

    orig_path = environ['PATH_INFO']
    name = shift_path_info(environ)

    if name == "":
        if have_swat:
            start_response('301 Redirect',
                [('Location', urljoin(application_uri(environ), 'swat')),])
            return []
        else:
            return render_placeholder(environ, start_response)
    elif have_swat and name == "swat":
        return swat.__call__(environ, start_response)
    else:
        status = '404 Not found'
        response_headers = [('Content-type', 'text/html')]
        start_response(status, response_headers)
        return ["The path %s (%s) was not found" % (orig_path, name)]


if __name__ == '__main__':
    from wsgiref import simple_server
    httpd = simple_server.make_server('localhost', 8090, __call__)
    print "Serving HTTP on port 8090..."
    httpd.serve_forever()
