"""The WSGI application and the handlers in the frontend module."""

import webapp2
from webapp2_extras import routes
from webapp2_extras import security
from webapp2_extras import sessions

import base_handler
import zenith_cross

class HomeHandler(base_handler.BaseHandler):
    def get(self):
        """Explain what this application does."""
        self.render_template('home.html')

class PrivateHandler(base_handler.BaseHandler):

    """Handler that requires a logged in user.

    Subclass this handler for your login protected routes.
    """

    def dispatch(self):
        """Override dispatch to check for a logged in user.

        We cannot simply extend dispatch() in BaseHandler because self.session
        requires self.session_store be set first.

        Alternative approaches considered:
        1. Create a decorator
            You would need to decorate every method. That is prone to
            accidentally missing one and opening a security hole. Overriding
            dispatch like we do here protects every method of the handler.
        2. Checking code in BaseHandler under a class attribute flag
            Handlers that require the check can set the flag to True.
            This means the superclass needs to know about the subclass.
            I prefer the onus of extending be on the subclass.
        """
        self.session_store = sessions.get_store(request=self.request)
        if 'hash' not in self.session:
            return self.redirect_to('login')
        try:
            # Bypass dispatch() in BaseHandler and call the version in its
            # parent class
            super(base_handler.BaseHandler, self).dispatch()
        finally:
            self.session_store.save_sessions(self.response)

    def get(self):
        """Show a private page only accessible by a logged in user."""
        values = {
            'hash': self.session.get('hash'),
            'state': self.session.get('state')
        }
        self.render_template('private.html', values)

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


_config = {
    'webapp2_extras.sessions': {
        # This is the only required configuration key
        'secret_key': zenith_cross.SECRET_KEY,
        # Default cookie name (same as Flask; Django uses "sessionid")
        'cookie_name': 'session',
        # Tie session expiration to the cookie
        'session_max_age': None,
        'cookie_args': {
            # Limit the cookie to the current session (until browser close)
            'max_age': None,
            # Limit the cookie to this subdomain because App Engine
            # applications are implemented as subdomains of appspot.com
            'domain': None,
            # Make the cookie valid for all paths of the application
            'path': '/',
            # The development web server does not support HTTPS
            'secure': not zenith_cross.DEBUG,
            # Disallow JavaScript access to the cookie
            'httponly': True
        }
    }
}
"""Dictionary webapp2 configuration."""

app = webapp2.WSGIApplication([
    routes.PathPrefixRoute(r'/login', [
        # The redirect_uri for each identity provider
        # Comment out or remove as needed
        webapp2.Route(r'/facebook', handler=zenith_cross.FacebookCallback,
                      name='facebook_callback'),
        webapp2.Route(r'/github', handler=zenith_cross.GitHubCallback,
                      name='github_callback'),
        webapp2.Route(r'/google', handler=zenith_cross.GoogleCallback,
                      name='google_callback'),
        webapp2.Route(r'/linkedin', handler=zenith_cross.LinkedInCallback,
                      name='linkedin_callback'),
        webapp2.Route(r'/twitter', handler=zenith_cross.TwitterCallback,
                      name='twitter_callback'),
        # Default to the identity provider selection page
        webapp2.Route('/', handler=zenith_cross.LoginHandler, name='login')
    ]),
    webapp2.Route(r'/logout', handler=zenith_cross.LogoutHandler,
                  name='logout'),
    routes.RedirectRoute(r'/private/', handler=PrivateHandler,
                         strict_slash=True, name='private'),
    routes.RedirectRoute(r'/secret/', handler=SecretHandler,
                         strict_slash=True, name='secret'),
    webapp2.Route(r'/', handler=HomeHandler, name='home')
], config=_config, debug=zenith_cross.DEBUG)
