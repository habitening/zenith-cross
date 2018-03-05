"""The base request handler in its own module to prevent circular import."""

import webapp2
from webapp2_extras import jinja2

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
