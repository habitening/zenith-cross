"""webapp2 handlers and helpers to support federated login."""

import base64
import hashlib
import hmac
import json
import logging
import os.path
import time
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

_PROVIDERS = frozenset(['Facebook', 'GitHub', 'Google'])
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
    # Cannot use iterkeys() because we are modifying the dictionary
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
        urlfetch._URLFetchResult object to the response of the fetch or
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

def parse_JSON_response(response, default=None):
    """Return the JSON object in response or default."""
    if response is None:
        return default
    content_type = response.headers.get('Content-Type')
    if (isinstance(content_type, basestring) and
        content_type.startswith('application/json')):
        try:
            result = json.loads(response.content)
        except ValueError:
            return default
        else:
            return result
    return default

def hash_user_id(user_id, method, pepper=None, prefix=None):
    """Return user_id hashed with method and optionally pepper.

    This function alters the string user ID from an identity provider so it is
    not stored in plaintext. Use the hash as an indexed property in your
    account implementation if you want account entities with random IDs. If you
    will NEVER expose the path to the account entities, you can use the hash as
    the key.

    Be careful! The hash is not cryptographically strong. Unlike a
    username/password pair, user_id is the key and the value so we cannot use a
    random salt. If we did, then we would not be able to find the hash without
    storing the user_id in plaintext, defeating the original purpose.

    Args:
        user_id: String user ID from an identity provider.
        method: String name of a method from hashlib to use to generate the
            hash.
        pepper: Optional string secret constant stored in the configuration.
        prefix: Optional ASCII string prefix to prepend to the hash.
    Returns:
        String hashed user ID from an identity provider with optional prefix.
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
            if provider == 'facebook':
                return self.redirect(FacebookCallback.create_login_url(
                    callback_url, state))
            elif provider == 'github':
                return self.redirect(GitHubCallback.create_login_url(
                    callback_url, state))
            elif provider == 'google':
                return self.redirect(GoogleCallback.create_login_url(
                    callback_url, state))
            elif provider == 'twitter':
                # Twitter uses OAuth 1.0a which means more work
                auth_url, token, secret = TwitterCallback.create_login_url(
                    callback_url, state)
                if isinstance(auth_url, basestring) and (len(auth_url) > 0):
                    self.session['oauth_token'] = token
                    self.session['oauth_token_secret'] = secret
                    return self.redirect(auth_url)
                else:
                    break

        # Otherwise, unimplemented or unrecognized identity provider
        return self.redirect_to('login')

class LinkedInCallback(base_handler.BaseHandler):

    """Superclass for callback handlers based on OAuth 2.0."""

    CONFIG_KEY = 'LinkedIn'
    """String key for the LinkedIn configuration dictionary."""

    AUTHORIZATION_ENDPOINT = 'https://www.linkedin.com/oauth/v2/authorization'
    """String URL to the LinkedIn authorization endpoint."""

    TOKEN_ENDPOINT = 'https://www.linkedin.com/oauth/v2/accessToken'
    """String URL to the LinkedIn token endpoint."""

    PROFILE_ENDPOINT = 'https://api.linkedin.com/v1/people/~?format=json'
    """String URL to the LinkedIn basic profile endpoint."""

    def get(self):
        """Handle the redirect back to us."""
        if (('error' in self.request.GET) or
            ('error_description' in self.request.GET)):
            return self.after_logout()

        state = self.request.GET.get('state')
        if (not isinstance(state, basestring)) or (len(state) <= 0):
            return self.after_logout()
        expected_state = self.session.get('state')
        if state != expected_state:
            return self.after_logout()

        # Trade code for access token and use access token to get user ID
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
            user_id, CONFIG[self.CONFIG_KEY].get('method'),
            CONFIG[self.CONFIG_KEY].get('pepper'),
            self.CONFIG_KEY.lower() + '_')

        return self.after_login()

    @classmethod
    def create_login_url(cls, redirect_uri, state):
        """Return the URL to request a user's LinkedIn identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's LinkedIn identity.
        """
        parameters = {
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'r_basicprofile',
            'state': state
        }
        return cls.AUTHORIZATION_ENDPOINT + '?' + urllib.urlencode(parameters)

    @classmethod
    def get_access_token(cls, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
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
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'client_secret': CONFIG[cls.CONFIG_KEY].get('client_secret'),
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = fetch(cls.TOKEN_ENDPOINT,
                         payload, urlfetch.POST, headers)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            token = result.get('access_token')
            if isinstance(token, basestring) and (len(token) > 0):
                return token
        return None

    @classmethod
    def get_user_id(cls, access_token):
        """Return the LinkedIn user ID using access_token."""
        if not isinstance(access_token, basestring):
            return None
        if len(access_token) <= 0:
            return None

        headers = {'Authorization': 'Bearer ' + access_token}
        response = fetch(cls.PROFILE_ENDPOINT, headers=headers)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            user_id = result.get('id')
            if isinstance(user_id, basestring) and (len(user_id) > 0):
                return user_id
        return None

class FacebookCallback(LinkedInCallback):

    CONFIG_KEY = 'Facebook'
    """String key for the Facebook configuration dictionary."""

    AUTHORIZATION_ENDPOINT = 'https://www.facebook.com/v2.12/dialog/oauth'
    """String URL to the Facebook authorization endpoint."""

    TOKEN_ENDPOINT = 'https://graph.facebook.com/v2.12/oauth/access_token'
    """String URL to the Facebook token endpoint."""

    PROFILE_ENDPOINT = 'https://graph.facebook.com/v2.12/me'
    """String URL to the Facebook public profile endpoint."""

    def get(self):
        """Handle the Facebook redirect back to us."""
        if 'error_reason' in self.request.GET:
            # Facebook includes an extra error_reason parameter
            return self.after_logout()
        return super(FacebookCallback, self).get()

    @classmethod
    def create_login_url(cls, redirect_uri, state):
        """Return the URL to request a user's Facebook identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's Facebook identity.
        """
        parameters = {
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'public_profile',
            'state': state
        }
        return cls.AUTHORIZATION_ENDPOINT + '?' + urllib.urlencode(parameters)

    @classmethod
    def get_access_token(cls, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
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

        parameters = {
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'client_secret': CONFIG[cls.CONFIG_KEY].get('client_secret'),
            'code': code,
            'redirect_uri': redirect_uri
        }
        url = cls.TOKEN_ENDPOINT + '?' + urllib.urlencode(parameters)
        response = fetch(url)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            token = result.get('access_token')
            if isinstance(token, basestring) and (len(token) > 0):
                return token
        return None

    @classmethod
    def get_appsecret_proof(cls, access_token):
        """Return the app secret proof to verify a Graph API call.

        Args:
            access_token: String access token
        Returns:
            String hex digest of the sha256 hash of access_token,
            using the app secret as the key.
        """
        return hmac.new(CONFIG[cls.CONFIG_KEY].get('client_secret'),
                        access_token, hashlib.sha256).hexdigest()

    @classmethod
    def get_user_id(cls, access_token):
        """Return the Facebook user ID using access_token."""
        if not isinstance(access_token, basestring):
            return None
        if len(access_token) <= 0:
            return None

        parameters = {
            'access_token': access_token,
            'appsecret_proof': cls.get_appsecret_proof(access_token),
            'fields': 'id,name'
        }
        url = cls.PROFILE_ENDPOINT + '?' + urllib.urlencode(parameters)
        response = fetch(url)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            user_id = result.get('id')
            if isinstance(user_id, basestring) and (len(user_id) > 0):
                return user_id
        return None

class GitHubCallback(LinkedInCallback):

    CONFIG_KEY = 'GitHub'
    """String key for the GitHub configuration dictionary."""

    AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize'
    """String URL to the GitHub authorization endpoint."""

    TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token'
    """String URL to the GitHub token endpoint."""

    PROFILE_ENDPOINT = 'https://api.github.com/graphql'
    """String URL to the GitHub GraphQL API v4 endpoint."""

    @classmethod
    def create_login_url(cls, redirect_uri, state):
        """Return the URL to request a user's GitHub identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's GitHub identity.
        """
        parameters = {
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'redirect_uri': redirect_uri,
            'scope': 'user',
            'state': state
        }
        allow_signup = CONFIG[cls.CONFIG_KEY].get('allow_signup')
        if allow_signup in ('true', 'false'):
            parameters['allow_signup'] = allow_signup
        return cls.AUTHORIZATION_ENDPOINT + '?' + urllib.urlencode(parameters)

    @classmethod
    def get_access_token(cls, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
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
            'client_id': CONFIG[cls.CONFIG_KEY].get('client_id'),
            'client_secret': CONFIG[cls.CONFIG_KEY].get('client_secret'),
            'code': code,
            'redirect_uri': redirect_uri,
            'state': state
        })
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = fetch(cls.TOKEN_ENDPOINT,
                         payload, urlfetch.POST, headers)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            token = result.get('access_token')
            if isinstance(token, basestring) and (len(token) > 0):
                return token
        return None

    @classmethod
    def get_user_id(cls, access_token):
        """Return the GitHub user ID using access_token."""
        if not isinstance(access_token, basestring):
            return None
        if len(access_token) <= 0:
            return None

        payload = '{"query": "query { viewer { email id login name }}"}'
        headers = {'Authorization': 'Bearer ' + access_token}
        response = fetch(cls.PROFILE_ENDPOINT,
                         payload, urlfetch.POST, headers)
        result = parse_JSON_response(response)
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

class TwitterCallback(base_handler.BaseHandler):

    REQUEST_ENDPOINT = 'https://api.twitter.com/oauth/request_token'
    """String URL to the Twitter request token endpoint."""

    AUTHORIZATION_ENDPOINT = 'https://api.twitter.com/oauth/authenticate'
    """String URL to the Twitter authorization endpoint."""

    TOKEN_ENDPOINT = 'https://api.twitter.com/oauth/access_token'
    """String URL to the Twitter token endpoint."""

    PROFILE_ENDPOINT = '\
https://api.twitter.com/1.1/account/verify_credentials.json'
    """String URL to the Twitter public profile endpoint."""

    def get(self):
        """Handle the Twitter redirect back to us."""
        if (('error' in self.request.GET) or
            ('error_description' in self.request.GET)):
            return self.after_logout()

        token = self.request.GET.get('oauth_token')
        if (not isinstance(token, basestring)) or (len(token) <= 0):
            return self.after_logout()
        expected_token = self.session.get('oauth_token')
        if token != expected_token:
            return self.after_logout()

        # Trade for access token and use access token to get user ID
        verifier = self.request.GET.get('oauth_verifier')
        if (not isinstance(verifier, basestring)) or (len(verifier) <= 0):
            return self.after_logout()
        secret = self.session.get('oauth_token_secret')
        access_token, access_secret = self.get_access_token(
            token, secret, verifier)
        if ((not isinstance(access_token, basestring)) or
            (len(access_token) <= 0)):
            return self.after_logout()
        if ((not isinstance(access_secret, basestring)) or
            (len(access_secret) <= 0)):
            return self.after_logout()
        user_id = self.get_user_id(access_token, access_secret)
        if (not isinstance(user_id, basestring)) or (len(user_id) <= 0):
            return self.after_logout()

        self.session['access_token'] = access_token
        self.session['access_token_secret'] = access_secret
        self.session['user_id'] = user_id
        self.session['hash'] = hash_user_id(
            user_id, CONFIG['Twitter'].get('method'),
            CONFIG['Twitter'].get('pepper'), 'twitter_')

        return self.after_login()

    @staticmethod
    def _percent_encode(s):
        """Return the string s percent encoded per Twitter specification."""
        if isinstance(s, str):
            return urllib.quote(s, '')
        elif isinstance(s, unicode):
            return urllib.quote(s.encode('utf-8'), '')
        else:
            raise TypeError('s must be a string.')

    @classmethod
    def _get_signature(cls, base_url, parameters, method, nonce, timestamp,
                       token='', token_secret=''):
        """Return the OAuth 1.0a HMAC-SHA1 signature for a HTTP request.

        Args:
            base_url: String base URL of the endpoint, minus any query string
                or hash parameters.
            parameters: Dictionary of parameters included in the request.
            method: String HTTP method of the request. Must be "GET" or "POST".
            nonce: String unique token for the request.
            timestamp: String number of seconds since the Unix epoch at the
                point the request is generated.
            token: Optional string OAuth token.
            token_secret: Optional string token secret.
        Returns:
            String OAuth 1.0a HMAC-SHA1 signature for a Twitter HTTP request.
        """
        encoded_parameters = dict(
            [(cls._percent_encode(key), cls._percent_encode(value))
             for key, value in parameters.iteritems()])
        for key, value in [
            ('oauth_consumer_key', CONFIG['Twitter'].get('consumer_key')),
            ('oauth_nonce', nonce),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', timestamp),
            ('oauth_token', token),
            ('oauth_version', '1.0')]:
            if not isinstance(value, basestring):
                continue
            if len(value) <= 0:
                continue
            encoded_key = cls._percent_encode(key)
            encoded_value = cls._percent_encode(value)
            encoded_parameters[encoded_key] = encoded_value

        keys = encoded_parameters.keys()
        keys.sort()
        parameter_string = '&'.join(
            [key + '=' + encoded_parameters[key] for key in keys])
        print parameter_string

        # Double encoding parameter_string is correct
        base_string = '&'.join([method, cls._percent_encode(base_url),
                                cls._percent_encode(parameter_string)])
        print base_string
        signing_key = '&'.join([CONFIG['Twitter'].get('consumer_secret'),
                                token_secret])
        print signing_key
        hmac_obj = hmac.new(signing_key, base_string, hashlib.sha1)
        print hmac_obj.hexdigest()
        return base64.b64encode(hmac_obj.digest())

    @classmethod
    def _get_authorization_header(cls, nonce, signature, timestamp,
                                  callback='', token=''):
        """Return the Authorization header value for Twitter.

        Args:
            nonce: String unique token for the request.
            signature: String OAuth 1.0a HMAC-SHA1 signature.
            timestamp: String number of seconds since the Unix epoch at the
                point the request is generated.
            callback: Optional string URL to this callback handler.
            token: Optional string OAuth token.
        Returns:
            String Authorization header value for Twitter.
        """
        parts = []
        for key, value in [
            ('oauth_callback', callback),
            ('oauth_consumer_key', CONFIG['Twitter'].get('consumer_key')),
            ('oauth_nonce', nonce),
            ('oauth_signature', signature),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', timestamp),
            ('oauth_token', token),
            ('oauth_version', '1.0')]:
            if not isinstance(value, basestring):
                continue
            if len(value) <= 0:
                continue
            parts.append('{0}="{1}"'.format(cls._percent_encode(key),
                                            cls._percent_encode(value)))

        return 'OAuth ' + ', '.join(parts)

    @classmethod
    def _twitter_fetch(cls, base_url, parameters, method,
                       token='', token_secret=''):
        """Return the response of an OAuth 1.0a HTTP request to Twitter.

        Args:
            base_url: String base URL of the endpoint, minus any query string
                or hash parameters.
            parameters: Dictionary of parameters included in the request.
            method: String HTTP method of the request. Must be "GET" or "POST".
            token: Optional string OAuth token.
            token_secret: Optional string token secret.
        Returns:
            urlfetch._URLFetchResult object to the response or
            None if an error occurred or a response other than 200 was
            returned.
        """
        if not isinstance(base_url, basestring):
            raise TypeError('base_url must be a non-empty string.')
        if len(base_url) <= 0:
            raise ValueError('base_url must be a non-empty string.')
        if not isinstance(parameters, dict):
            raise TypeError('parameters must be a dict.')
        if not isinstance(method, basestring):
            raise TypeError('method must be "GET" or "POST".')
        method = method.strip().upper()
        if method not in ('GET', 'POST'):
            raise ValueError('method must be "GET" or "POST".')

        timestamp = str(long(time.time()))
        # oauth_nonce is not used for anything so cheat with the timestamp
        nonce = 'nonce' + timestamp
        signature = cls._get_signature(base_url, parameters, method, nonce,
                                       timestamp, token, token_secret)
        callback = parameters.get('oauth_callback', '')
        headers = {
            'Authorization': cls._get_authorization_header(
                nonce, signature, timestamp, callback, token)
        }
        if method == 'GET':
            url = base_url + '?' + urllib.urlencode(parameters)
            return fetch(url, headers=headers)
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            return fetch(base_url, urllib.urlencode(parameters),
                         urlfetch.POST, headers)

    @classmethod
    def create_login_url(cls, redirect_uri, state):
        """Return the URL to request a user's Twitter identity.

        Args:
            redirect_uri: String URL to this callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's Twitter identity
            String request token which should match oauth_token on callback
            String token secret
        """
        parameters = {
            'oauth_callback': redirect_uri
        }
        response = cls._twitter_fetch(cls.REQUEST_ENDPOINT, parameters, 'POST')
        if response is None:
            return None, None, None
        result = urlparse.parse_qs(response.content)
        if isinstance(result, dict):
            if result.get('oauth_callback_confirmed') == 'true':
                token = result.get('oauth_token')
                secret = result.get('oauth_token_secret')
                url = cls.AUTHORIZATION_ENDPOINT
                url += '?' + urllib.urlencode({'oauth_token': token})
                return url, token, secret
        return None, None, None

    @classmethod
    def get_access_token(cls, token, secret, verifier):
        """Exchange the request token for an access token.

        Args:
            token: String request token.
            secret: String token secret.
            verifier: String oauth_verifier parameter in the callback.
        Returns:
            String access token
            String token secret
        """
        if not isinstance(token, basestring):
            return None, None
        if len(token) <= 0:
            return None, None
        if not isinstance(secret, basestring):
            return None, None
        if len(secret) <= 0:
            return None, None
        if not isinstance(verifier, basestring):
            return None, None
        if len(verifier) <= 0:
            return None, None

        parameters = {
            'oauth_verifier': verifier
        }
        response = cls._twitter_fetch(cls.TOKEN_ENDPOINT, parameters, 'POST',
                                      token, secret)
        if response is None:
            return None, None
        result = urlparse.parse_qs(response.content)
        if isinstance(result, dict):
            print result
            token = result.get('oauth_token')
            secret = result.get('oauth_token_secret')
            return token, secret
        return None, None

    @classmethod
    def get_user_id(cls, token, secret):
        """Return the Twitter user ID using the access token.

        Args:
            token: String access token.
            secret: String token secret.
        Returns:
            String Twitter user ID.
        """
        if not isinstance(token, basestring):
            return None
        if len(token) <= 0:
            return None
        if not isinstance(secret, basestring):
            return None
        if len(secret) <= 0:
            return None

        parameters = {
            'include_entities': 'false',
            'skip_status': 'true',
            'include_email': 'false'
        }
        response = cls._twitter_fetch(cls.PROFILE_ENDPOINT, parameters, 'GET',
                                      token, secret)
        result = parse_JSON_response(response)
        if isinstance(result, dict):
            user_id = result.get('id_str')
            if isinstance(user_id, basestring) and (len(user_id) > 0):
                return user_id
        return None
