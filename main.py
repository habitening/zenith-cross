"""The WSGI application and the handlers in the frontend module."""

import os

import webapp2
from webapp2_extras import routes
from webapp2_extras import security

import base_handler
import zenith_cross

class HomeHandler(base_handler.BaseHandler):
    def get(self):
        """Explain what this application does."""
        self.render_template('home.html')

class PrivateHandler(base_handler.BaseHandler):
    def get(self):
        """Show a private page only accessible by an authenticated user."""
        self.render_template('private.html')

class SecretHandler(base_handler.BaseHandler):
    def get(self):
        """Show a page of random secret keys."""
        values = {
            'alphanumerics': [security.generate_random_string(
                length=64, pool=security.ALPHANUMERIC)
                              for i in xrange(16)],
            'printables': [security.generate_random_string(
                length=64, pool=security.ASCII_PRINTABLE)
                           for i in xrange(16)]
        }
        self.render_template('secret.html', values)


# Detect if the code is running on the development web server
_debug = os.environ.get('SERVER_SOFTWARE', '').startswith('Dev')

app = webapp2.WSGIApplication([
    routes.PathPrefixRoute(r'/login', [
        webapp2.Route(r'/github', handler=zenith_cross.GitHubCallback,
                      name='github_callback'),
        webapp2.Route(r'/google', handler=zenith_cross.GoogleCallback,
                      name='google_callback'),
        webapp2.Route('/', handler=zenith_cross.LoginHandler, name='login')
    ]),
    webapp2.Route(r'/logout', handler=zenith_cross.LogoutHandler,
                  name='logout'),
    routes.RedirectRoute(r'/private/', handler=PrivateHandler,
                         strict_slash=True, name='private'),
    routes.RedirectRoute(r'/secret/', handler=SecretHandler,
                         strict_slash=True, name='secret'),
    webapp2.Route(r'/', handler=HomeHandler, name='home')
], debug=_debug)
