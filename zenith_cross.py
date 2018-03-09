"""webapp2 handlers and helpers to support federated login."""

import json
import logging
import os.path
import urllib
import urlparse

from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.runtime import apiproxy_errors

import webapp2
from webapp2_extras import security
import yaml

import base_handler

_PATH_TO_CONFIG = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               'config.yaml'))
"""String path to the YAML configuration file."""

_PROVIDERS = frozenset(['GitHub', 'Google'])
"""Set of string keys of the implemented identity providers."""

def _parse_config(path, required_keys=['webapp2']):
    """Return a configuration dictionary parsed from the YAML file at path.

    Args:
        path: String ASCII path to the YAML configuration file.
        required_keys: Iterable of string required keys in the configuration
            dictionary.
    Raises:
        IndexError if a required key is missing from the configuration
        dictionary.
    Returns:
        Configuration dictionary parsed from the YAML file at path.
    """
    if not isinstance(path, str):
        raise TypeError('path must be a valid ASCII path to a YAML file.')
    if not os.path.isfile(path):
        raise ValueError('path must be a valid ASCII path to a YAML file.')

    config = {}
    with open(path, 'r') as yaml_file:
        try:
            for document in yaml.safe_load_all(yaml_file):
                if isinstance(document, dict):
                    config = document
                    break
        except yaml.YAMLError:
            pass

    expected = list(_PROVIDERS)
    for key in required_keys:
        if not isinstance(key, basestring):
            continue
        if len(key) <= 0:
            continue
        expected.append(key)
        if key not in config:
            raise IndexError(
                'Missing required key in CONFIG: {0}'.format(key))

    expected = frozenset(expected)
    for provider in config.keys():
        # Remove unimplemented or unrecognized identity providers
        if provider not in expected:
            del config[provider]
            continue
        # Force a configuration value to be a string
        for key, value in config[provider].iteritems():
            if isinstance(value, bool):
                config[provider][key] = str(value).lower()
            elif isinstance(value, (int, long, float)):
                config[provider][key] = str(value)

    return config

CONFIG = _parse_config(_PATH_TO_CONFIG)
"""Configuration dictionary."""

def fetch(url, payload=None, method=urlfetch.GET, headers={}, deadline=5):
    """Return the response from fetching url or None.

    This is a wrapper around urlfetch.fetch() with error checks.

    Args:
        url: String URL to fetch.
        payload: Optional POST, PUT, or PATCH payload.
        method: One of the GET, POST, HEAD, PUT, DELETE, PATCH constants in
            urlfetch specifying the type of the request.
            Defaults to urlfetch.GET.
        headers: Optional dictionary of HTTP headers to send with the request.
        deadline: Optional positive integer maximum number of seconds to wait
            for a response up to a limit of 60 seconds.
            Defaults to 5 seconds.
    Returns:
        urlfetch._URLFetchResult object to the result of the fetch or
        None if an error occurred or a response other than 200 was returned.
    """
    if not isinstance(headers, dict):
        raise TypeError('headers must be a dict.')
    if (not isinstance(deadline, int)) or (deadline <= 0) or (60 < deadline):
        deadline = 5
    try:
        response = urlfetch.fetch(
            url, payload=payload, method=method, headers=headers,
            allow_truncated=False, follow_redirects=False,
            deadline=deadline, validate_certificate=True)
    except urlfetch.Error as error:
        logging.error('urlfetch.Error ({0}).'.format(error.__class__.__name__))
        return None
    except apiproxy_errors.Error as error:
        logging.error('apiproxy_errors.Error ({0}).'.format(
            error.__class__.__name__))
        return None
    if response.status_code == 200:
        return response
    else:
        return None

def hash_user_id(user_id, method, pepper=None, prefix=None):
    """Return user_id hashed with method and optionally pepper.

    This function alters the string ID from an identity provider so it is not
    stored in plaintext. Use the hash as an indexed property in your account
    implementation if you want account entities with random IDs. If you will
    not expose the path to the account entities, you can use the hash as the
    key.

    Be careful. The hash is not cryptographically strong. Unlike a
    username/password pair, user_id is the key and the value so we cannot use a
    random salt. If we did, then we would not be able to find the hash without
    storing the user_id in plaintext, defeating the original purpose.

    Args:
        user_id: String ID from an identity provider.
        method: String name of a method from hashlib to use to generate the
            hash.
        pepper: Optional string secret constant stored in the configuration.
        prefix: Optional ASCII string prefix to prepend to the hash.
    Returns:
        String hashed ID from an identity provider with optional prefix.
    """
    if not isinstance(user_id, basestring):
        raise TypeError('user_id must be a non-empty string.')
    if len(user_id) <= 0:
        raise ValueError('user_id must be a non-empty string.')
    if not isinstance(method, basestring):
        raise TypeError('method must be a non-empty string.')
    if len(method) <= 0:
        raise ValueError('method must be a non-empty string.')

    hashed_id = security.hash_password(user_id, method, pepper=pepper)
    if isinstance(prefix, str) and (len(prefix) > 0):
        return prefix + hashed_id
    else:
        return hashed_id


class LogoutHandler(base_handler.BaseHandler):
    def get(self):
        """Discard the session."""
        self.session['_logout'] = True
        return self.after_logout()

class LoginHandler(base_handler.BaseHandler):

    """Handler for the identity provider selection page.

    This is called the NASCAR screen in FirebaseUI due to the way the identity
    provider buttons look like the sponsor decals on the cars.
    """

    def get(self):
        """Show a form with the available identity providers alphabetically."""
        values = {
            'providers': sorted([key for key in CONFIG.iterkeys()
                                 if key in _PROVIDERS])
        }
        self.render_template('login.html', values)

    def post(self):
        """Redirect the user to the selected identity provider."""
        for key in CONFIG.iterkeys():
            provider = key.strip().lower()
            if ('provider:' + provider) not in self.request.POST:
                continue

            if self.app.debug:
                # The development web server does not support HTTPS
                scheme = 'http'
            else:
                scheme = 'https'
            callback_url = self.uri_for(provider + '_callback',
                                        _scheme=scheme)
            state = security.generate_random_string(
                length=32, pool=security.ALPHANUMERIC)
            # Store the state in the session so it can be verified on callback
            # It is not a secret because it is exposed in the redirect
            self.session['state'] = state
            if provider == 'github':
                return self.redirect(GitHubCallback.create_login_url(
                    callback_url, state))
            elif provider == 'google':
                return self.redirect(GoogleCallback.create_login_url(
                    callback_url, state))

        # Otherwise, unimplemented or unrecognized identity provider
        return self.redirect_to('login')

class GitHubCallback(base_handler.BaseHandler):

    LOGIN_ENDPOINT = 'https://github.com/login/oauth/authorize'
    """String URL to the GitHub login endpoint."""

    ACCESS_TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token'
    """String URL to the GitHub access token endpoint."""

    GRAPHQL_ENDPOINT = 'https://api.github.com/graphql'
    """String URL to the GitHub GraphQL API v4 endpoint."""

    def get(self):
        """Handle the GitHub redirect back to us."""
        if (('error' in self.request.GET) or
            ('error_description' in self.request.GET)):
            return self.after_logout()

        state = self.request.GET.get('state')
        expected_state = self.session.get('state')
        if state != expected_state:
            return self.after_logout()

        # Trade code for access_token and use access_token to get user_id
        code = self.request.GET.get('code')
        if (not isinstance(code, basestring)) or (len(code) <= 0):
            return self.after_logout()
        token = self.get_access_token(code, self.request.path_url, state)
        if (not isinstance(token, basestring)) or (len(token) <= 0):
            return self.after_logout()
        user_id = self.get_user_id(token)
        if (not isinstance(user_id, basestring)) or (len(user_id) <= 0):
            return self.after_logout()

        self.session['access_token'] = token
        self.session['user_id'] = user_id
        self.session['hash'] = hash_user_id(
            user_id, CONFIG['GitHub'].get('method'),
            CONFIG['GitHub'].get('pepper'), 'github_')

        return self.after_login()

    @staticmethod
    def create_login_url(redirect_uri, state):
        """Return the URL to request a user's GitHub identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's GitHub identity.
        """
        parameters = {
            'client_id': CONFIG['GitHub'].get('client_id'),
            'redirect_uri': redirect_uri,
            'scope': 'user',
            'state': state
        }
        allow_signup = CONFIG['GitHub'].get('allow_signup')
        if allow_signup in ('true', 'false'):
            parameters['allow_signup'] = allow_signup
        return GitHubCallback.LOGIN_ENDPOINT + '?' + urllib.urlencode(
            parameters)

    @staticmethod
    def get_access_token(code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary code parameter.
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String access token or None if an error occurred.
        """
        if not isinstance(code, basestring):
            return None
        if len(code) <= 0:
            return None

        payload = urllib.urlencode({
            'client_id': CONFIG['GitHub'].get('client_id'),
            'client_secret': CONFIG['GitHub'].get('client_secret'),
            'code': code,
            'redirect_uri': redirect_uri,
            'state': state
        })
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = fetch(GitHubCallback.ACCESS_TOKEN_ENDPOINT,
                         payload, urlfetch.POST, headers)
        if response is None:
            return None
        content_type = response.headers.get('Content-Type')
        if (isinstance(content_type, basestring) and
            content_type.startswith('application/json')):
            try:
                result = json.loads(response.content)
            except ValueError:
                return None
            if isinstance(result, dict):
                token = result.get('access_token')
                if isinstance(token, basestring) and (len(token) > 0):
                    return token
        return None

    @staticmethod
    def get_user_id(access_token):
        """Return the GitHub user ID using access_token."""
        if not isinstance(access_token, basestring):
            return None
        if len(access_token) <= 0:
            return None

        payload = '{"query": "query { viewer { email id login name }}"}'
        headers = {'Authorization': 'bearer ' + access_token}
        response = fetch(GitHubCallback.GRAPHQL_ENDPOINT,
                         payload, urlfetch.POST, headers)
        if response is None:
            return None
        content_type = response.headers.get('Content-Type')
        if (isinstance(content_type, basestring) and
            content_type.startswith('application/json')):
            try:
                result = json.loads(response.content)
            except ValueError:
                return None
            if isinstance(result, dict):
                data = result.get('data')
                if isinstance(data, dict):
                    data = data.get('viewer')
                    if isinstance(data, dict):
                        user_id = data.get('id')
                        if (isinstance(user_id, basestring) and
                            (len(user_id) > 0)):
                            return user_id
        return None

class GoogleCallback(base_handler.BaseHandler):
    def get(self):
        """Handle the Google redirect back to us."""
        current_user = users.get_current_user()
        if isinstance(current_user, users.User):
            user_id = current_user.user_id()
            if isinstance(user_id, basestring) and (len(user_id) > 0):
                self.session['user_id'] = user_id
                self.session['hash'] = hash_user_id(
                    user_id, CONFIG['Google'].get('method'),
                    CONFIG['Google'].get('pepper'), 'google_')
                return self.after_login()

        # If login was canceled or failed
        return self.after_logout()

    @staticmethod
    def create_login_url(redirect_uri, state):
        """Return the URL to request a user's Google identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's Google identity.
        """
        # Delegate to the App Engine Users API
        return users.create_login_url(redirect_uri)
