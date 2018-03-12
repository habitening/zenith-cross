"""Test the zenith-cross helpers."""

import hashlib
import hmac
import os.path
import urllib

from google.appengine.api import users

from webapp2_extras import security

import zenith_cross
import test

class ConfigurationTest(test.BaseTestCase):
    def test_parse_config(self):
        """Test parsing a YAML configuration file."""
        for value in [None, 42, [], u'fo\u00f6b\u00e4r']:
            self.assertRaises(TypeError, zenith_cross._parse_config, value)
        for value in ['', 'foobar', 'foobar.yaml']:
            self.assertRaises(ValueError, zenith_cross._parse_config, value)
        for value in ['zenith_cross.py', 'test_zenith_cross.py']:
            self.assertRaises(IndexError, zenith_cross._parse_config, value)
        self.assertEqual(zenith_cross._parse_config('config.yaml'),
                         zenith_cross.CONFIG)

    def test_bad_config(self):
        """Test the bad configuration file."""
        path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'sample', 'bad_config.yaml'))
        self.assertRaises(IndexError, zenith_cross._parse_config, path)

    def test_google(self):
        """Test the Google configuration file."""
        path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'sample', 'google.yaml'))
        config = zenith_cross._parse_config(path)
        self.assertEqual(config, {
            'Google': {
                'method': 'sha1',
                'pepper': 'alphabet'
            },
            'webapp2': {
                'secret_key': 'my-super-secret-key'
            }
        })

    def test_twitter(self):
        """Test the Twitter configuration file."""
        path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'sample', 'twitter.yaml'))
        config = zenith_cross._parse_config(path)
        self.assertEqual(config, {
##            'Twitter': {
##                'method': 'sha256',
##                'pepper': 'Tweet',
##                'consumer_key': 'L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg'
##                'consumer_secret':
##                'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw'
##            },
            'webapp2': {
                'secret_key': 'my-super-secret-key'
            }
        })

    def test_fetch(self):
        """Test fetching a URL."""
        for value in [None, 42, '']:
            self.assertIsNone(
                zenith_cross.fetch('http://example.com', method=value))
            self.assertRaises(TypeError, zenith_cross.fetch,
                              'http://example.com', headers=value)

        response = zenith_cross.fetch(
            'https://status.cloud.google.com/incidents.json')
        self.assertIsNotNone(response)
        content_type = response.headers.get('Content-Type')
        self.assertIsInstance(content_type, basestring)
        self.assertTrue(content_type.startswith('application/json'))

        result = zenith_cross.parse_JSON_response(response)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, list)

    def test_parse_JSON_response(self):
        """Test parsing a JSON response."""
        self.assertIsNone(zenith_cross.parse_JSON_response(None))
        for value in [None, 42, '', []]:
            self.assertEqual(zenith_cross.parse_JSON_response(None, value),
                             value)

    def test_hash_user_id(self):
        """Test hashing a user ID."""
        user_id = 'foobar'
        for value in [None, 42, []]:
            self.assertRaises(TypeError, zenith_cross.hash_user_id,
                              value, 'sha1')
            self.assertRaises(TypeError, zenith_cross.hash_user_id,
                              user_id, value)
        self.assertRaises(ValueError, zenith_cross.hash_user_id, '', 'sha256')
        self.assertRaises(ValueError, zenith_cross.hash_user_id, user_id, '')

        for method in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
            expected = security.hash_password(user_id, method)
            self.assertEqual(zenith_cross.hash_user_id(user_id, method),
                             expected)
            self.assertEqual(zenith_cross.hash_user_id(user_id, method, None),
                             expected)
            self.assertEqual(zenith_cross.hash_user_id(user_id, method, ''),
                             expected)
            for prefix in [None, 42, '', []]:
                self.assertEqual(
                    zenith_cross.hash_user_id(user_id, method, prefix=prefix),
                    expected)
                self.assertEqual(
                    zenith_cross.hash_user_id(user_id, method, None, prefix),
                    expected)
                self.assertEqual(
                    zenith_cross.hash_user_id(user_id, method, '', prefix),
                    expected)
            self.assertEqual(
                zenith_cross.hash_user_id(user_id, method, prefix='prefix_'),
                'prefix_' + expected)

            expected = security.hash_password(user_id, method, pepper='barbaz')
            self.assertEqual(
                zenith_cross.hash_user_id(user_id, method, 'barbaz'),
                expected)
            for prefix in [None, 42, '', []]:
                self.assertEqual(zenith_cross.hash_user_id(
                    user_id, method, 'barbaz', prefix), expected)
            self.assertEqual(zenith_cross.hash_user_id(
                user_id, method, 'barbaz', 'prefix_'), 'prefix_' + expected)

class OAuth2Test(test.BaseTestCase):
    @property
    def handler_class(self):
        """Return webapp2.RequestHandler class containing all the helpers."""
        # LinkedIn has the truest OAuth 2.0 implementation (no deviations)
        return zenith_cross.LinkedInCallback

    def setUp(self):
        """Modify the configuration for the test."""
        super(OAuth2Test, self).setUp()

        self.key = self.handler_class.CONFIG_KEY
        """String key to the configuration dictionary."""

        self.original_config = None
        if self.key in zenith_cross.CONFIG:
            self.original_config = zenith_cross.CONFIG[self.key].copy()

        zenith_cross.CONFIG[self.key] = {
            'method': 'sha1',
            'pepper': 'pepper',
            'client_id': 'client_id',
            'client_secret': 'client_secret'
        }
        """Dictionary configuration to use in the tests."""

        self.redirect_uris = [
            'foobar', '/foobar', '/foobar/', '/foo/bar',
            'http://example.com', 'https://example.com'
        ]
        """List of string redirect_uri to use in the tests."""

    def tearDown(self):
        """Restore the configuration."""
        super(OAuth2Test, self).tearDown()

        if self.original_config is not None:
            zenith_cross.CONFIG[self.key] = self.original_config

    def test_config_key(self):
        """Test the key for the LinkedIn configuration dictionary."""
        self.assertEqual(self.key, 'LinkedIn')

    def test_endpoints(self):
        """Test the various endpoints are defined and non-empty."""
        for name in [
            'AUTHORIZATION_ENDPOINT', 'TOKEN_ENDPOINT', 'PROFILE_ENDPOINT']:
            endpoint = getattr(self.handler_class, name)
            self.assertIsInstance(endpoint, basestring)
            self.assertTrue(endpoint.startswith('https://'))

    def test_create_login_url(self):
        """Test the URL to request a user's LinkedIn identity."""
        parameters = {
            'client_id': 'client_id',
            'response_type': 'code',
            'scope': 'r_basicprofile',
            'state': 'state'
        }
        for url in self.redirect_uris:
            parameters['redirect_uri'] = url
            expected = self.handler_class.AUTHORIZATION_ENDPOINT
            expected += '?' + urllib.urlencode(parameters)
            self.assertEqual(self.handler_class.create_login_url(
                url, parameters['state']), expected)

    def test_get_access_token(self):
        """Test exchanging the temporary code parameter for an access token."""
        for value in [None, 42, '', []]:
            self.assertIsNone(self.handler_class.get_access_token(
                value, 'redirect_uri', 'state'))
        self.assertIsNone(self.handler_class.get_access_token(
            'code', 'redirect_uri', 'state'))

    def test_get_user_id(self):
        """Test getting the user ID using an access token."""
        for value in [None, 42, '', []]:
            self.assertIsNone(self.handler_class.get_user_id(value))
        self.assertIsNone(self.handler_class.get_user_id('access_token'))

class FacebookTest(OAuth2Test):
    @property
    def handler_class(self):
        """Return webapp2.RequestHandler class containing all the helpers."""
        return zenith_cross.FacebookCallback

    def test_config_key(self):
        """Test the key for the Facebook configuration dictionary."""
        self.assertEqual(self.key, 'Facebook')

    def test_create_login_url(self):
        """Test the URL to request a user's Facebook identity."""
        parameters = {
            'client_id': 'client_id',
            'response_type': 'code',
            'scope': 'public_profile',
            'state': 'state'
        }
        for url in self.redirect_uris:
            parameters['redirect_uri'] = url
            expected = self.handler_class.AUTHORIZATION_ENDPOINT
            expected += '?' + urllib.urlencode(parameters)
            self.assertEqual(self.handler_class.create_login_url(
                url, parameters['state']), expected)

    def test_get_appsecret_proof(self):
        """Test signing the access token with client_secret."""
        for token in ['foobar', 'access_token']:
            self.assertEqual(
                self.handler_class.get_appsecret_proof(token),
                hmac.new('client_secret', token, hashlib.sha256).hexdigest())

class GitHubTest(OAuth2Test):
    @property
    def handler_class(self):
        """Return webapp2.RequestHandler class containing all the helpers."""
        return zenith_cross.GitHubCallback

    def test_config_key(self):
        """Test the key for the GitHub configuration dictionary."""
        self.assertEqual(self.key, 'GitHub')

    def test_create_login_url(self):
        """Test the URL to request a user's GitHub identity."""
        parameters = {
            'client_id': 'client_id',
            'scope': 'user',
            'state': 'state'
        }
        for url in self.redirect_uris:
            parameters['redirect_uri'] = url
            expected = self.handler_class.AUTHORIZATION_ENDPOINT
            expected += '?' + urllib.urlencode(parameters)
            self.assertEqual(self.handler_class.create_login_url(
                url, parameters['state']), expected)
            for value in [None, 42, '', [], 'False', 'True', 'no', 'yes']:
                zenith_cross.CONFIG[self.key]['allow_signup'] = value
                self.assertEqual(self.handler_class.create_login_url(
                    url, parameters['state']), expected)
            for value in ['false', 'true']:
                zenith_cross.CONFIG[self.key]['allow_signup'] = value
                parameters['allow_signup'] = value
                expected = self.handler_class.AUTHORIZATION_ENDPOINT
                expected += '?' + urllib.urlencode(parameters)
                self.assertEqual(self.handler_class.create_login_url(
                    url, parameters['state']), expected)

            # Reset for the next iteration
            del zenith_cross.CONFIG[self.key]['allow_signup']
            del parameters['allow_signup']

class GoogleTest(test.BaseTestCase):
    def test_create_login_url(self):
        """Test the URL to request a user's Google identity."""
        for value in ['foobar', '/foobar', '/foobar/', '/foo/bar',
                      'http://example.com', 'https://example.com']:
            self.assertEqual(
                zenith_cross.GoogleCallback.create_login_url(value, value),
                users.create_login_url(value))
