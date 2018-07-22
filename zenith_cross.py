"""Request handlers and helpers to support federated login."""

import base64
import hashlib
import hmac
import json
import logging
import os
import os.path
import time
import urllib
import urlparse

from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.runtime import apiproxy_errors

from webapp2_extras import security
import yaml

import base_handler

def _fetch_url(url, payload=None, method=urlfetch.GET, headers={}, deadline=5):
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

def _parse_JSON_response(response, default=None):
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

def _is_valid(token):
    """Return True if token is a non-empty string and False otherwise."""
    return (isinstance(token, basestring) and (len(token) > 0))

def _get_string_value(dictionary, key, default=None):
    """Return the string value for key in dictionary or default."""
    if isinstance(dictionary, dict) and isinstance(key, str):
        value = dictionary.get(key)
        if _is_valid(value):
            return value
    return default

def _hash_user_id(user_id, method, pepper=None, prefix=None):
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
        method: String name of a method from hashlib to use to hash
            the user ID.
        pepper: Optional string secret constant stored in the configuration.
        prefix: Optional ASCII string prefix to prepend to the hash.
    Returns:
        String hashed user ID from an identity provider with optional prefix.
    """
    if not isinstance(user_id, basestring):
        raise TypeError('user_id must be a non-empty string.')
    if len(user_id) <= 0:
        raise ValueError('user_id must be a non-empty string.')
    if not hasattr(hashlib, method):
        raise ValueError('method must be in hashlib.')

    hashed_id = security.hash_password(user_id, method, pepper=pepper)
    if isinstance(prefix, str) and (len(prefix) > 0):
        return prefix + hashed_id
    else:
        return hashed_id


class GoogleFlow(object):

    """Simplest authentication flow with the fewest parameters."""

    def __init__(self, method, pepper):
        """Initialize this authentication flow.

        Args:
            method: String name of a method from hashlib to use to hash
                the user ID.
            pepper: String ASCII secret constant stored in the configuration.
        """
        if not hasattr(hashlib, method):
            raise ValueError('method must be in hashlib.')
        if not isinstance(pepper, str):
            raise TypeError('pepper must be a non-empty ASCII string.')
        if len(pepper) <= 0:
            raise ValueError('pepper must be a non-empty ASCII string.')

        self.method = method
        """String name of a method from hashlib to use to hash the user ID."""

        self.pepper = pepper
        """String secret constant to add to the hash of the user ID."""

    def get_name(self):
        """Return the string name of this identity provider."""
        return 'Google'

    def create_login_url(self, redirect_uri, *args):
        """Return the URL to request a user's Google identity.

        Args:
            redirect_uri: String URI to the callback handler.
        Returns:
            String URL to request a user's Google identity.
        """
        # Delegate to the App Engine Users API
        return users.create_login_url(redirect_uri)

    def _get_user_id(self, **kwargs):
        """Return the Google user ID."""
        current_user = users.get_current_user()
        if isinstance(current_user, users.User):
            user_id = current_user.user_id()
            if _is_valid(user_id):
                return user_id
        return None

    def get_hashed_user_id(self, user_id=None, **kwargs):
        """Return the hashed user ID.

        I abused the Python keyword argument machinery here to avoid having to
        rewrite this method for each class.

        This method only accepts keyword arguments to support the polymorphic
        _get_user_id() method it calls. Those arguments should match the
        underlying _get_user_id() call if user_id is not valid.

        Args:
            user_id: Optional string user ID to hash.
            **kwargs: Optional keyword arguments to pass to _get_user_id() to
                retrieve the user ID.
        """
        if not _is_valid(user_id):
            user_id = self._get_user_id(**kwargs)
        if _is_valid(user_id):
            return _hash_user_id(user_id, self.method, self.pepper,
                                 self.get_name().lower() + '_')
        return None

class LinkedInFlow(GoogleFlow):

    """The truest OAuth 2.0 implementation."""

    def __init__(self, method, pepper, client_id, client_secret):
        """Initialize this authentication flow.

        Args:
            method: String name of a method from hashlib to use to hash
                the user ID.
            pepper: String ASCII secret constant stored in the configuration.
            client_id: String "API Key" value generated when you registered
                your application.
            client_secret: String "Secret Key" value generated when you
                registered your application.
        """
        if not isinstance(client_id, str):
            raise TypeError('client_id must be a non-empty ASCII string.')
        if len(client_id) <= 0:
            raise ValueError('client_id must be a non-empty ASCII string.')
        if not isinstance(client_secret, str):
            raise TypeError('client_secret must be a non-empty ASCII string.')
        if len(client_secret) <= 0:
            raise ValueError('client_secret must be a non-empty ASCII string.')
        super(LinkedInFlow, self).__init__(method, pepper)

        self.client_id = client_id
        """String "API Key" value generated when you registered."""

        self.client_secret = client_secret
        """String "Secret Key" value generated when you registered."""

    def get_name(self):
        """Return the string name of this identity provider."""
        return 'LinkedIn'

    def _get_authorization_endpoint(self):
        """Return the string URL to the LinkedIn authorization endpoint."""
        return 'https://www.linkedin.com/oauth/v2/authorization'

    def _get_token_endpoint(self):
        """Return the string URL to the LinkedIn token endpoint."""
        return 'https://www.linkedin.com/oauth/v2/accessToken'

    def _get_profile_endpoint(self):
        """Return the string URL to the LinkedIn basic profile endpoint."""
        return 'https://api.linkedin.com/v1/people/~?format=json'

    def create_login_url(self, redirect_uri, state):
        """Return the URL to request a user's LinkedIn identity.

        Args:
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's LinkedIn identity.
        """
        parameters = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'r_basicprofile',
            'state': state
        }
        url = self._get_authorization_endpoint() + '?'
        url += urllib.urlencode(parameters)
        return url

    def get_access_token(self, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String access token or None if an error occurred.
        """
        if not _is_valid(code):
            return None

        payload = urllib.urlencode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = _fetch_url(self._get_token_endpoint(),
                              payload, urlfetch.POST, headers)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'access_token')

    def _get_user_id(self, access_token=None, **kwargs):
        """Return the LinkedIn user ID using access_token.

        Args:
            access_token: String access token.
        Returns:
            String LinkedIn user ID.
        """
        if not _is_valid(access_token):
            return None

        headers = {'Authorization': 'Bearer ' + access_token}
        response = _fetch_url(self._get_profile_endpoint(), headers=headers)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'id')

class FacebookFlow(LinkedInFlow):
    def get_name(self):
        """Return the string name of this identity provider."""
        return 'Facebook'

    def _get_authorization_endpoint(self):
        """Return the string URL to the Facebook authorization endpoint."""
        return 'https://www.facebook.com/v3.0/dialog/oauth'

    def _get_token_endpoint(self):
        """Return the string URL to the Facebook token endpoint."""
        return 'https://graph.facebook.com/v3.0/oauth/access_token'

    def _get_profile_endpoint(self):
        """Return the string URL to the Facebook public profile endpoint."""
        return 'https://graph.facebook.com/v3.0/me'

    def create_login_url(self, redirect_uri, state):
        """Return the URL to request a user's Facebook identity.

        Args:
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's Facebook identity.
        """
        parameters = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'public_profile',
            'state': state
        }
        url = self._get_authorization_endpoint() + '?'
        url += urllib.urlencode(parameters)
        return url

    def get_access_token(self, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String access token or None if an error occurred.
        """
        if not _is_valid(code):
            return None

        parameters = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri
        }
        url = self._get_token_endpoint() + '?' + urllib.urlencode(parameters)
        response = _fetch_url(url)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'access_token')

    def _get_appsecret_proof(self, access_token):
        """Return the app secret proof to verify a Graph API call.

        Args:
            access_token: String access token.
        Returns:
            String hex digest of the sha256 hash of access_token,
            using the app secret as the key.
        """
        return hmac.new(self.client_secret, access_token,
                        hashlib.sha256).hexdigest()

    def _get_user_id(self, access_token=None, **kwargs):
        """Return the Facebook user ID using access_token.

        Args:
            access_token: String access token.
        Returns:
            String Facebook user ID.
        """
        if not _is_valid(access_token):
            return None

        parameters = {
            'access_token': access_token,
            'appsecret_proof': self._get_appsecret_proof(access_token),
            'fields': 'id,name'
        }
        url = self._get_profile_endpoint() + '?' + urllib.urlencode(parameters)
        response = _fetch_url(url)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'id')

class GitHubFlow(LinkedInFlow):

    """GitHub also allows you to sign up."""

    def __init__(self, method, pepper, client_id, client_secret,
                 allow_signup=None):
        """Initialize this authentication flow.

        Args:
            method: String name of a method from hashlib to use to hash
                the user ID.
            pepper: String ASCII secret constant stored in the configuration.
            client_id: String "API Key" value generated when you registered
                your application.
            client_secret: String "Secret Key" value generated when you
                registered your application.
            allow_signup: Optional string indicating whether or not
                unauthenticated users will be offered an option to sign up for
                GitHub during the OAuth flow.
        """
        super(GitHubFlow, self).__init__(
            method, pepper, client_id, client_secret)

        if (isinstance(allow_signup, basestring) and
            (allow_signup.strip().lower() in ('on', 'true', 'yes'))):
            self.allow_signup = 'true'
        else:
            self.allow_signup = 'false'

    def get_name(self):
        """Return the string name of this identity provider."""
        return 'GitHub'

    def _get_authorization_endpoint(self):
        """Return the string URL to the GitHub authorization endpoint."""
        return 'https://github.com/login/oauth/authorize'

    def _get_token_endpoint(self):
        """Return the string URL to the GitHub token endpoint."""
        return 'https://github.com/login/oauth/access_token'

    def _get_profile_endpoint(self):
        """Return the string URL to the GitHub GraphQL API v4 endpoint."""
        return 'https://api.github.com/graphql'

    def create_login_url(self, redirect_uri, state):
        """Return the URL to request a user's GitHub identity.

        Args:
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String URL to request a user's GitHub identity.
        """
        parameters = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': 'user',
            'state': state,
            'allow_signup': self.allow_signup
        }
        url = self._get_authorization_endpoint() + '?'
        url += urllib.urlencode(parameters)
        return url

    def get_access_token(self, code, redirect_uri, state):
        """Exchange the temporary code parameter for an access token.

        Args:
            code: String temporary authorization code parameter.
            redirect_uri: String URI to the callback handler.
            state: String unguessable random string to protect against
                cross-site request forgery attacks.
        Returns:
            String access token or None if an error occurred.
        """
        if not _is_valid(code):
            return None

        payload = urllib.urlencode({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'state': state
        })
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = _fetch_url(self._get_token_endpoint(),
                              payload, urlfetch.POST, headers)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'access_token')

    def _get_user_id(self, access_token=None, **kwargs):
        """Return the GitHub user ID using access_token.

        Args:
            access_token: String access token.
        Returns:
            String GitHub user ID.
        """
        if not _is_valid(access_token):
            return None

        payload = '{"query": "query { viewer { email id login name }}"}'
        headers = {'Authorization': 'Bearer ' + access_token}
        response = _fetch_url(self._get_profile_endpoint(),
                              payload, urlfetch.POST, headers)
        result = _parse_JSON_response(response)
        if isinstance(result, dict):
            data = result.get('data')
            if isinstance(data, dict):
                data = data.get('viewer')
                return _get_string_value(data, 'id')
        return None

class TwitterFlow(GoogleFlow):

    """OAuth 1.0a implementation."""

    def __init__(self, method, pepper, consumer_key, consumer_secret):
        """Initialize this authentication flow.

        Args:
            method: String name of a method from hashlib to use to hash
                the user ID.
            pepper: String ASCII secret constant stored in the configuration.
            consumer_key: String value from checking the settings page for
                your application on apps.twitter.com.
            consumer_secret: String value from checking the settings page for
                your application on apps.twitter.com.
        """
        if not isinstance(consumer_key, str):
            raise TypeError('consumer_key must be a non-empty ASCII string.')
        if len(consumer_key) <= 0:
            raise ValueError('consumer_key must be a non-empty ASCII string.')
        if not isinstance(consumer_secret, str):
            raise TypeError(
                'consumer_secret must be a non-empty ASCII string.')
        if len(consumer_secret) <= 0:
            raise ValueError(
                'consumer_secret must be a non-empty ASCII string.')
        super(TwitterFlow, self).__init__(method, pepper)

        self.consumer_key = consumer_key
        """String consumer key from the settings page."""

        self.consumer_secret = consumer_secret
        """String consumer secret from the settings page."""

    def get_name(self):
        """Return the string name of this identity provider."""
        return 'Twitter'

    def _get_request_endpoint(self):
        """Return the string URL to the Twitter request token endpoint."""
        return 'https://api.twitter.com/oauth/request_token'

    def _get_authorization_endpoint(self):
        """Return the string URL to the Twitter authorization endpoint."""
        return 'https://api.twitter.com/oauth/authenticate'

    def _get_token_endpoint(self):
        """Return the string URL to the Twitter token endpoint."""
        return 'https://api.twitter.com/oauth/access_token'

    def _get_profile_endpoint(self):
        """Return the string URL to the Twitter public profile endpoint."""
        return 'https://api.twitter.com/1.1/account/verify_credentials.json'

    @staticmethod
    def _percent_encode(s):
        """Return the string s percent encoded per Twitter specification."""
        if isinstance(s, str):
            return urllib.quote(s, '')
        elif isinstance(s, unicode):
            return urllib.quote(s.encode('utf-8'), '')
        else:
            raise TypeError('s must be a string.')

    def _get_signature(self, base_url, parameters, method, nonce, timestamp,
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
            [(self._percent_encode(key), self._percent_encode(value))
             for key, value in parameters.iteritems()])
        for key, value in [
            ('oauth_consumer_key', self.consumer_key),
            ('oauth_nonce', nonce),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', timestamp),
            ('oauth_token', token),
            ('oauth_version', '1.0')]:
            if not _is_valid(value):
                continue
            encoded_key = self._percent_encode(key)
            encoded_value = self._percent_encode(value)
            encoded_parameters[encoded_key] = encoded_value

        keys = encoded_parameters.keys()
        keys.sort()
        parameter_string = '&'.join(
            [key + '=' + encoded_parameters[key] for key in keys])
        print parameter_string

        # Double encoding parameter_string is correct
        base_string = '&'.join([method, self._percent_encode(base_url),
                                self._percent_encode(parameter_string)])
        print base_string
        signing_key = '&'.join([self.consumer_secret, token_secret])
        print signing_key
        hmac_obj = hmac.new(signing_key, base_string, hashlib.sha1)
        print hmac_obj.hexdigest()
        return base64.b64encode(hmac_obj.digest())

    def _get_authorization_header(self, nonce, signature, timestamp,
                                  callback='', token=''):
        """Return the Authorization header value for Twitter.

        Args:
            nonce: String unique token for the request.
            signature: String OAuth 1.0a HMAC-SHA1 signature.
            timestamp: String number of seconds since the Unix epoch at the
                point the request is generated.
            callback: Optional string URL to the callback handler.
            token: Optional string OAuth token.
        Returns:
            String Authorization header value for Twitter.
        """
        parts = []
        for key, value in [
            ('oauth_callback', callback),
            ('oauth_consumer_key', self.consumer_key),
            ('oauth_nonce', nonce),
            ('oauth_signature', signature),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', timestamp),
            ('oauth_token', token),
            ('oauth_version', '1.0')]:
            if not _is_valid(value):
                continue
            parts.append('{0}="{1}"'.format(self._percent_encode(key),
                                            self._percent_encode(value)))

        return 'OAuth ' + ', '.join(parts)

    def _twitter_fetch(self, base_url, parameters, method,
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
        if not isinstance(method, str):
            raise TypeError('method must be "GET" or "POST".')
        method = method.strip().upper()
        if method not in ('GET', 'POST'):
            raise ValueError('method must be "GET" or "POST".')

        timestamp = str(long(time.time()))
        # oauth_nonce is not used for anything so cheat with the timestamp
        nonce = 'nonce' + timestamp
        signature = self._get_signature(base_url, parameters, method, nonce,
                                        timestamp, token, token_secret)
        callback = parameters.get('oauth_callback', '')
        headers = {
            'Authorization': self._get_authorization_header(
                nonce, signature, timestamp, callback, token)
        }
        if method == 'GET':
            url = base_url + '?' + urllib.urlencode(parameters)
            return _fetch_url(url, headers=headers)
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            return _fetch_url(base_url, urllib.urlencode(parameters),
                              urlfetch.POST, headers)

    def create_login_url(self, redirect_uri, state):
        """Return the URL to request a user's Twitter identity.

        Args:
            redirect_uri: String URI to the callback handler.
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
        response = self._twitter_fetch(self._get_request_endpoint(),
                                       parameters, 'POST')
        if response is None:
            return None, None, None
        result = urlparse.parse_qs(response.content)
        if isinstance(result, dict):
            if result.get('oauth_callback_confirmed') == 'true':
                token = result.get('oauth_token')
                secret = result.get('oauth_token_secret')
                url = self._get_authorization_endpoint() + '?'
                url += urllib.urlencode({'oauth_token': token})
                return url, token, secret
        return None, None, None

    def get_access_token(self, token, secret, verifier):
        """Exchange the request token for an access token.

        Args:
            token: String request token.
            secret: String token secret.
            verifier: String oauth_verifier parameter in the callback.
        Returns:
            String access token
            String token secret
        """
        if not _is_valid(token):
            return None, None
        if not _is_valid(secret):
            return None, None
        if not _is_valid(verifier):
            return None, None

        parameters = {
            'oauth_verifier': verifier
        }
        response = self._twitter_fetch(self._get_token_endpoint(),
                                       parameters, 'POST', token, secret)
        if response is None:
            return None, None
        result = urlparse.parse_qs(response.content)
        if isinstance(result, dict):
            print result
            token = result.get('oauth_token')
            secret = result.get('oauth_token_secret')
            return token, secret
        return None, None

    def _get_user_id(self, token=None, secret=None, **kwargs):
        """Return the Twitter user ID using the access token.

        Args:
            token: String access token.
            secret: String token secret.
        Returns:
            String Twitter user ID.
        """
        if not _is_valid(token):
            return None
        if not _is_valid(secret):
            return None

        parameters = {
            'include_entities': 'false',
            'skip_status': 'true',
            'include_email': 'false'
        }
        response = self._twitter_fetch(self._get_profile_endpoint(),
                                       parameters, 'GET', token, secret)
        result = _parse_JSON_response(response)
        return _get_string_value(result, 'id_str')


def _parse_config(path):
    """Parse the configuration in the YAML file at path.

    Args:
        path: String ASCII path to the YAML configuration file.
    Raises:
        IndexError if a required key is missing from the configuration file.
    Returns:
        Dictionary of identity providers as GoogleFlow objects
        String secret key for webapp2.sessions
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

    # Read the secret key for webapp2.sessions
    if 'webapp2' not in config:
        raise IndexError(
            'webapp2 secret_key is REQUIRED in the YAML configuration file.')
    secret_key = config['webapp2'].get('secret_key')
    if not isinstance(secret_key, basestring):
        raise IndexError(
            'webapp2 secret_key is REQUIRED in the YAML configuration file.')

    # Read the configurations for the identity providers
    provider_map = {}
    for key, value in config.iteritems():
        if not isinstance(value, dict):
            continue
        provider = key.strip().lower()
        flow = None
        if provider == 'facebook':
            flow = FacebookFlow(
                value.get('method'), value.get('pepper'),
                value.get('client_id'), value.get('client_secret'))
        elif provider == 'github':
            flow = GitHubFlow(
                value.get('method'), value.get('pepper'),
                value.get('client_id'), value.get('client_secret'),
                value.get('allow_signup'))
        elif provider == 'google':
            flow = GoogleFlow(value.get('method'), value.get('pepper'))
        elif provider == 'linkedin':
            flow = LinkedInFlow(
                value.get('method'), value.get('pepper'),
                value.get('client_id'), value.get('client_secret'))
        elif provider == 'twitter':
            flow = TwitterFlow(
                value.get('method'), value.get('pepper'),
                value.get('consumer_key'), value.get('consumer_secret'))
        else:
            # Unimplemented or unrecognized identity provider
            continue
        if flow is not None:
            provider_map[flow.get_name()] = flow

    return provider_map, secret_key

# Detect if the code is running on the development web server
DEBUG = os.environ.get('SERVER_SOFTWARE', '').startswith('Dev')

if DEBUG:
    _PATH_TO_CONFIG = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                   'development.yaml'))
    """String path to the development YAML configuration file."""
else:
    _PATH_TO_CONFIG = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                   'production.yaml'))
    """String path to the production YAML configuration file."""

_PROVIDER_MAP, SECRET_KEY = _parse_config(_PATH_TO_CONFIG)
"""Dictionary of identity providers as GoogleFlow subclasses."""
"""String secret key for webapp2.sessions."""


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
        providers = _PROVIDER_MAP.keys()
        providers.sort()
        values = {
            'providers': providers
        }
        self.render_template('login.html', values)

    def post(self):
        """Redirect the user to the selected identity provider."""
        for name, flow in _PROVIDER_MAP.iteritems():
            key = 'provider:' + name.lower()
            if key not in self.request.POST:
                continue

            if self.app.debug:
                # The development web server does not support HTTPS
                scheme = 'http'
            else:
                scheme = 'https'
            callback_url = self.uri_for(name.lower() + '_callback',
                                        _scheme=scheme)
            if not _is_valid(callback_url):
                break
            state = security.generate_random_string(
                length=32, pool=security.ALPHANUMERIC)
            # Store the state in the session so it can be verified on callback
            # It is not a secret because it is exposed in the redirect
            self.session['state'] = state
            if name == 'Twitter':
                # Twitter uses OAuth 1.0a which means more work
                auth_url, token, secret = flow.create_login_url(
                    callback_url, state)
                if _is_valid(auth_url):
                    self.session['oauth_token'] = token
                    self.session['oauth_token_secret'] = secret
                    return self.redirect(auth_url)
                else:
                    break
            else:
                return self.redirect(flow.create_login_url(
                    callback_url, state))

        # Otherwise, unimplemented or unrecognized identity provider
        return self.redirect_to('login')

class LinkedInCallback(base_handler.BaseHandler):
    def get(self):
        """Handle the LinkedIn redirect back to us."""
        if (('error' in self.request.GET) or
            ('error_description' in self.request.GET)):
            return self.after_logout()

        state = self.request.GET.get('state')
        if not _is_valid(state):
            return self.after_logout()
        expected_state = self.session.get('state')
        if state != expected_state:
            return self.after_logout()

        # Trade code for access token and use access token to get user ID
        code = self.request.GET.get('code')
        if not _is_valid(code):
            return self.after_logout()
        flow = self.get_flow()
        if not isinstance(flow, LinkedInFlow):
            return self.after_logout()
        token = flow.get_access_token(code, self.request.path_url, state)
        if not _is_valid(token):
            return self.after_logout()

        hashed_user_id = flow.get_hashed_user_id(access_token=token)
        if _is_valid(hashed_user_id):
            self.session['access_token'] = token
            self.session['hash'] = hashed_user_id
            return self.after_login()

        # If login was canceled or failed
        return self.after_logout()

    def get_flow(self):
        """Return the LinkedInFlow object for this callback handler."""
        flow = _PROVIDER_MAP.get('LinkedIn')
        if not isinstance(flow, LinkedInFlow):
            logging.error(
                'LinkedIn was not configured as an identity provider!')
        return flow

class FacebookCallback(LinkedInCallback):
    def get(self):
        """Handle the Facebook redirect back to us."""
        if 'error_reason' in self.request.GET:
            # Facebook includes an extra error_reason parameter
            return self.after_logout()
        return super(FacebookCallback, self).get()

    def get_flow(self):
        """Return the FacebookFlow object for this callback handler."""
        flow = _PROVIDER_MAP.get('Facebook')
        if not isinstance(flow, FacebookFlow):
            logging.error(
                'Facebook was not configured as an identity provider!')
        return flow

class GitHubCallback(LinkedInCallback):
    def get_flow(self):
        """Return the GitHubFlow object for this callback handler."""
        flow = _PROVIDER_MAP.get('GitHub')
        if not isinstance(flow, GitHubFlow):
            logging.error(
                'GitHub was not configured as an identity provider!')
        return flow

class GoogleCallback(base_handler.BaseHandler):
    def get(self):
        """Handle the Google redirect back to us."""
        flow = _PROVIDER_MAP.get('Google')
        if not isinstance(flow, GoogleFlow):
            logging.error(
                'Google was not configured as an identity provider!')
            return self.after_logout()

        hashed_user_id = flow.get_hashed_user_id()
        if _is_valid(hashed_user_id):
            self.session['hash'] = hashed_user_id
            return self.after_login()

        # If login was canceled or failed
        return self.after_logout()

class TwitterCallback(base_handler.BaseHandler):
    def get(self):
        """Handle the Twitter redirect back to us."""
        if (('error' in self.request.GET) or
            ('error_description' in self.request.GET)):
            return self.after_logout()

        token = self.request.GET.get('oauth_token')
        if not _is_valid(token):
            return self.after_logout()
        expected_token = self.session.get('oauth_token')
        if token != expected_token:
            return self.after_logout()

        # Trade for access token and use access token to get user ID
        verifier = self.request.GET.get('oauth_verifier')
        if not _is_valid(verifier):
            return self.after_logout()
        secret = self.session.get('oauth_token_secret')
        flow = _PROVIDER_MAP.get('Twitter')
        if not isinstance(flow, TwitterFlow):
            logging.error(
                'Twitter was not configured as an identity provider!')
            return self.after_logout()
        access_token, access_secret = flow.get_access_token(
            token, secret, verifier)
        if not _is_valid(access_token):
            return self.after_logout()
        if not _is_valid(access_secret):
            return self.after_logout()

        hashed_user_id = flow.get_hashed_user_id(token=access_token,
                                                 secret=access_secret)
        if _is_valid(hashed_user_id):
            self.session['access_token'] = access_token
            self.session['access_token_secret'] = access_secret
            self.session['hash'] = hashed_user_id
            return self.after_login()

        # If login was canceled or failed
        return self.after_logout()
