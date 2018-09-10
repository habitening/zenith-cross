"""The base request handler in its own module to prevent circular import."""

import webapp2
from webapp2_extras import jinja2
from webapp2_extras import sessions

import models

def reverse(name, *args, **kwargs):
    """Return the URI for a route named name."""
    return webapp2.uri_for(name, *args, **kwargs)

def jinja2_factory(app):
    """Custom Jinja2 factory method to insert our own extensions."""
    config = {
        'globals': {'reverse': reverse},
        'filters': {}
    }
    return jinja2.Jinja2(app, config)

class BaseHandler(webapp2.RequestHandler):

    """The base request handler."""

    def dispatch(self):
        """Add a session store to the handler."""
        self.session_store = sessions.get_store(request=self.request)
        try:
            return super(BaseHandler, self).dispatch()
        finally:
            self.session_store.save_sessions(self.response)

    def after_login(self):
        """Redirect to the route to show after logging in."""
        return self.redirect_to('private')

    def after_logout(self):
        """Redirect to the route to show after logging out."""
        return self.redirect_to('home')

    @webapp2.cached_property
    def jinja2(self):
        """Cached Jinja2 environment as per webapp2 documentation."""
        return jinja2.get_jinja2(factory=jinja2_factory, app=self.app)

    def render_template(self, template_name, values={}):
        """Render values in the template and write it to the response.

        Args:
            template_name: String name of the template in the "templates/"
                directory.
            values: Optional context dictionary.
        """
        if not isinstance(template_name, str):
            raise TypeError('template_name must be a non-empty ASCII string.')
        if len(template_name) <= 0:
            raise ValueError('template_name must be a non-empty ASCII string.')
        if not isinstance(values, dict):
            raise TypeError('values must be a dict.')
        self.response.write(
            self.jinja2.render_template(template_name, **values))

    @webapp2.cached_property
    def flash(self):
        """Return a secure cookie session for flash messages.

        Django and Flask have a similar implementation. If you do not use flash
        messages, then no secure cookie is written.

            # To add a flash message
            self.flash.add_flash('Foobar!')
            # To get all flash messages
            messages = [value for value, level in self.flash.get_flashes()]

        It is fine that the flash messages are visible in a secure cookie
        because the user will see them in the next response any way.
        """
        # Need to supply a name to avoid using the same default cookie name
        return self.session_store.get_session(
            name='gordon', backend='securecookie')

    @webapp2.cached_property
    def session(self):
        """Return a datastore backed session for the default cookie name.

        DO NOT use this session for flash messages because it is kept in the
        datastore and adding flash messages will incur expensive datastore
        writes! There is a separate session for flash messages.
        """
        return self.session_store.get_session(
            factory=models.JSONSessionFactory)
