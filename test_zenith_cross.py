"""Test the zenith-cross helpers."""

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
##            },
            'webapp2': {
                'secret_key': 'my-super-secret-key'
            }
        })

    def test_fetch(self):
        """Test fetching a URL."""
        for value in [None, 42, '', []]:
            self.assertRaises(TypeError, zenith_cross.fetch,
                              'http://example.com', headers=value)

        response = zenith_cross.fetch(
            'https://status.cloud.google.com/incidents.json')
        self.assertIsNotNone(response)
        content_type = response.headers.get('Content-Type')
        self.assertIsInstance(content_type, basestring)
        self.assertTrue(content_type.startswith('application/json'))

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

class GitHubTest(test.BaseTestCase):
    def setUp(self):
        """Modify the GitHub configuration for the test."""
        super(GitHubTest, self).setUp()

        self.original_config = zenith_cross.CONFIG.get('GitHub').copy()

        zenith_cross.CONFIG['GitHub'] = {
            'method': 'sha1',
            'pepper': 'pepper',
            'client_id': 'client_id',
            'client_secret': 'client_secret'
        }
        """Dictionary GitHub configuration to use in the tests."""

    def tearDown(self):
        """Restore the GitHub configuration."""
        super(GitHubTest, self).tearDown()

        zenith_cross.CONFIG['GitHub'] = self.original_config

    def test_create_login_url(self):
        """Test the URL to request a user's GitHub identity."""
        parameters = {
            'client_id': 'client_id',
            'scope': 'user',
            'state': 'state'
        }
        for url in ['foobar', '/foobar', '/foobar/', '/foo/bar',
                    'http://example.com', 'https://example.com']:
            parameters['redirect_uri'] = url
            expected = zenith_cross.GitHubCallback.LOGIN_ENDPOINT + '?'
            expected += urllib.urlencode(parameters)
            self.assertEqual(zenith_cross.GitHubCallback.create_login_url(
                url, parameters['state']), expected)
            for value in [None, 42, '', [], 'False', 'True']:
                zenith_cross.CONFIG['GitHub']['allow_signup'] = value
                self.assertEqual(zenith_cross.GitHubCallback.create_login_url(
                    url, parameters['state']), expected)
            for value in ['false', 'true']:
                zenith_cross.CONFIG['GitHub']['allow_signup'] = value
                parameters['allow_signup'] = value
                expected = zenith_cross.GitHubCallback.LOGIN_ENDPOINT + '?'
                expected += urllib.urlencode(parameters)
                self.assertEqual(zenith_cross.GitHubCallback.create_login_url(
                    url, parameters['state']), expected)

            # Reset for the next iteration
            del zenith_cross.CONFIG['GitHub']['allow_signup']
            del parameters['allow_signup']

    def test_get_access_token(self):
        """Test exchanging the temporary code parameter for an access token."""
        for value in [None, 42, '', []]:
            self.assertIsNone(zenith_cross.GitHubCallback.get_access_token(
                value, 'redirect_uri', 'state'))
        self.assertIsNone(zenith_cross.GitHubCallback.get_access_token(
            'code', 'redirect_uri', 'state'))

    def test_get_user_id(self):
        """Test getting the GitHub user ID using an access token."""
        for value in [None, 42, '', []]:
            self.assertIsNone(zenith_cross.GitHubCallback.get_user_id(value))
        self.assertIsNone(
            zenith_cross.GitHubCallback.get_user_id('access_token'))

class GoogleTest(test.BaseTestCase):
    def test_create_login_url(self):
        """Test the URL to request a user's Google identity."""
        for value in ['foobar', '/foobar', '/foobar/', '/foo/bar',
                      'http://example.com', 'https://example.com']:
            self.assertEqual(
                zenith_cross.GoogleCallback.create_login_url(value, value),
                users.create_login_url(value))
