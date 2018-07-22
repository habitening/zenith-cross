"""Test the zenith-cross module."""

import hashlib
import hmac
import os.path
import urllib

from google.appengine.api import users

from webapp2_extras import security

import test
import zenith_cross

class HelperTest(test.BaseTestCase):
    def test_fetch_url(self):
        """Test fetching a URL."""
        for value in [None, 42, '']:
            self.assertIsNone(
                zenith_cross._fetch_url('http://example.com', method=value))
            self.assertRaises(TypeError, zenith_cross._fetch_url,
                              'http://example.com', headers=value)

        response = zenith_cross._fetch_url(
            'https://status.cloud.google.com/incidents.json')
        self.assertIsNotNone(response)
        content_type = response.headers.get('Content-Type')
        self.assertIsInstance(content_type, basestring)
        self.assertTrue(content_type.startswith('application/json'))

        result = zenith_cross._parse_JSON_response(response)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, list)

    def test_parse_JSON_response(self):
        """Test parsing a JSON response."""
        self.assertIsNone(zenith_cross._parse_JSON_response(None))
        for value in [None, 42, '', []]:
            self.assertEqual(zenith_cross._parse_JSON_response(None, value),
                             value)

    def test_is_valid(self):
        """Test whether a token is valid."""
        for value in [None, 42, '', []]:
            self.assertFalse(zenith_cross._is_valid(value))
        for value in ['foobar', 'baz', u'fo\u00f6b\u00e4r']:
            self.assertTrue(zenith_cross._is_valid(value))

    def test_get_string_value(self):
        """Test getting the string value for a key in a dictionary."""
        for value in [None, 42, '', []]:
            self.assertIsNone(zenith_cross._get_string_value(value, 'foobar'))
            self.assertEqual(
                zenith_cross._get_string_value(value, 'foobar', 'baz'), 'baz')
            self.assertIsNone(zenith_cross._get_string_value(
                {'foobar': value}, 'foobar'))
            self.assertEqual(zenith_cross._get_string_value(
                {'foobar': value}, 'foobar', 'baz'), 'baz')

        dictionary = {
            'foo': 42,
            'bar': 'foobar',
            'baz': u'fo\u00f6b\u00e4r'
        }
        self.assertIsNone(zenith_cross._get_string_value(dictionary, 'foobar'))
        self.assertIsNone(zenith_cross._get_string_value(dictionary, 'foo'))
        self.assertEqual(
            zenith_cross._get_string_value(dictionary, 'foobar', 'none'),
            'none')
        self.assertEqual(
            zenith_cross._get_string_value(dictionary, 'foo', 'none'), 'none')
        self.assertEqual(zenith_cross._get_string_value(dictionary, 'bar'),
                         'foobar')
        self.assertEqual(zenith_cross._get_string_value(dictionary, 'baz'),
                         u'fo\u00f6b\u00e4r')

    def test_hash_user_id(self):
        """Test hashing a user ID."""
        for value in [None, 42, []]:
            self.assertRaises(TypeError, zenith_cross._hash_user_id,
                              value, 'sha1')
        self.assertRaises(ValueError, zenith_cross._hash_user_id, '', 'sha256')
        self.assertRaises(ValueError, zenith_cross._hash_user_id, 'foobar', '')
        self.assertRaises(ValueError, zenith_cross._hash_user_id,
                          'foobar', 'baz')

        for method in hashlib.algorithms:
            for user_id in ['foobar', 'baz', u'fo\u00f6b\u00e4r']:
                expected = security.hash_password(user_id, method)
                self.assertEqual(
                    zenith_cross._hash_user_id(user_id, method), expected)
                self.assertEqual(
                    zenith_cross._hash_user_id(user_id, method, None),
                    expected)
                self.assertEqual(
                    zenith_cross._hash_user_id(user_id, method, ''), expected)
                for prefix in [None, 42, '', []]:
                    self.assertEqual(zenith_cross._hash_user_id(
                        user_id, method, prefix=prefix), expected)
                    self.assertEqual(zenith_cross._hash_user_id(
                        user_id, method, None, prefix), expected)
                    self.assertEqual(zenith_cross._hash_user_id(
                        user_id, method, '', prefix), expected)
                self.assertEqual(zenith_cross._hash_user_id(
                    user_id, method, prefix='prefix_'), 'prefix_' + expected)

                expected = security.hash_password(
                    user_id, method, pepper='barbaz')
                self.assertEqual(
                    zenith_cross._hash_user_id(user_id, method, 'barbaz'),
                    expected)
                for prefix in [None, 42, '', []]:
                    self.assertEqual(zenith_cross._hash_user_id(
                        user_id, method, 'barbaz', prefix), expected)
                self.assertEqual(zenith_cross._hash_user_id(
                    user_id, method, 'barbaz', 'prefix_'),
                                 'prefix_' + expected)

    def test_parse_config(self):
        """Test parsing a YAML configuration file."""
        for value in [None, 42, [], u'fo\u00f6b\u00e4r']:
            self.assertRaises(TypeError, zenith_cross._parse_config, value)
        for value in ['', 'foobar', 'foobar.yaml']:
            self.assertRaises(ValueError, zenith_cross._parse_config, value)
        for value in ['zenith_cross.py', 'test_zenith_cross.py']:
            self.assertRaises(IndexError, zenith_cross._parse_config, value)
        for filename in ['development.yaml', 'production.yaml']:
            provider_map, secret_key = zenith_cross._parse_config(filename)
            self.assertIsInstance(provider_map, dict)
            self.assertGreater(len(provider_map), 0)
            self.assertIsInstance(secret_key, basestring)
            self.assertGreater(len(secret_key), 0)

    def test_bad_config(self):
        """Test the bad configuration file."""
        path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'sample', 'bad_config.yaml'))
        self.assertRaises(IndexError, zenith_cross._parse_config, path)

    def test_google(self):
        """Test the Google configuration file."""
        path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            'sample', 'google.yaml'))
        provider_map, secret_key = zenith_cross._parse_config(path)
        self.assertIsInstance(provider_map, dict)
        self.assertEqual(len(provider_map), 1)
        flow = provider_map.get('Google')
        self.assertIsInstance(flow, zenith_cross.GoogleFlow)
        self.assertEqual(flow.method, 'sha1')
        self.assertEqual(flow.pepper, 'alphabet')
        self.assertEqual(secret_key, 'my-super-secret-key')

    def test_constants(self):
        """Test the zenith_cross constants."""
        if zenith_cross.DEBUG:
            expected = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                    'development.yaml'))
        else:
            expected = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                    'production.yaml'))
        self.assertEqual(zenith_cross._PATH_TO_CONFIG, expected)
        self.assertIsInstance(zenith_cross._PROVIDER_MAP, dict)
        self.assertGreater(len(zenith_cross._PROVIDER_MAP), 0)
        self.assertIsInstance(zenith_cross.SECRET_KEY, basestring)
        self.assertGreater(len(zenith_cross.SECRET_KEY), 0)

class GoogleFlowTest(test.BaseTestCase):
    def setUp(self):
        """Create a flow instance for the test."""
        super(GoogleFlowTest, self).setUp()

        self.flow = self.create_flow()
        """GoogleFlow instance to use in the tests."""

        self.redirect_uris = [
            'foobar', '/foobar', '/foobar/', '/foo/bar',
            'http://example.com', 'https://example.com'
        ]
        """List of string redirect_uri to use in the tests."""

    def create_flow(self):
        """Return a GoogleFlow instance to use in the tests."""
        return zenith_cross.GoogleFlow('sha256', 'pepper')

    def test_sanity(self):
        """Test the GoogleFlow instance used in the tests."""
        self.assertIsInstance(self.flow, zenith_cross.GoogleFlow)
        self.assertEqual(self.flow.method, 'sha256')
        self.assertEqual(self.flow.pepper, 'pepper')
        self.assertEqual(self.flow.get_name(), 'Google')
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', 'sha256', 'pepper', 'google_'))

    def test_initialize(self):
        """Test initializing a GoogleFlow instance."""
        for value in [None, 42, [], u'fo\u00f6b\u00e4r']:
            self.assertRaises(TypeError, zenith_cross.GoogleFlow,
                              'sha1', value)
        self.assertRaises(ValueError, zenith_cross.GoogleFlow, '', 'pepper')
        self.assertRaises(ValueError, zenith_cross.GoogleFlow,
                          'foobar', 'pepper')
        self.assertRaises(ValueError, zenith_cross.GoogleFlow, 'sha256', '')

        for method in hashlib.algorithms:
            for pepper in ['foobar', 'pepper']:
                flow = zenith_cross.GoogleFlow(method, pepper)
                self.assertEqual(flow.method, method)
                self.assertEqual(flow.pepper, pepper)
                self.assertEqual(self.flow.get_name(), 'Google')

    def test_create_login_url(self):
        """Test the URL to request a user's Google identity."""
        for uri in self.redirect_uris:
            expected = users.create_login_url(uri)
            self.assertEqual(self.flow.create_login_url(uri), expected)
            self.assertEqual(self.flow.create_login_url(uri, uri), expected)
            self.assertEqual(self.flow.create_login_url(uri, uri, uri),
                             expected)

    def test_get_user_id(self):
        """Test getting the Google user ID."""
        self.assertIsNone(self.flow._get_user_id())
        self.assertIsNone(self.flow._get_user_id(foo=None))
        self.assertIsNone(self.flow._get_user_id(foo=None, bar=42))

        # Simulate a login in the testbed
        expected = 'test'
        self.testbed.setup_env(
            USER_ID=expected, USER_EMAIL='test@example.com', overwrite=True)
        self.assertEqual(self.flow._get_user_id(), expected)
        self.assertEqual(self.flow._get_user_id(foo=None), expected)
        self.assertEqual(self.flow._get_user_id(foo=None, bar=42), expected)

    def test_get_hashed_user_id(self):
        """Test getting the hashed Google user ID."""
        self.assertIsNone(self.flow.get_hashed_user_id())
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None))
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None, bar=42))
        for value in [None, 42, '', []]:
            self.assertIsNone(self.flow.get_hashed_user_id(user_id=value))

        # Test hashing a user ID
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', self.flow.method, self.flow.pepper,
                             self.flow.get_name().lower() + '_'))

        # Simulate a login in the testbed
        expected = zenith_cross._hash_user_id(
            'test', self.flow.method, self.flow.pepper,
            self.flow.get_name().lower() + '_')
        self.testbed.setup_env(
            USER_ID='test', USER_EMAIL='test@example.com', overwrite=True)
        self.assertEqual(self.flow.get_hashed_user_id(), expected)
        self.assertEqual(self.flow.get_hashed_user_id(foo=None), expected)
        self.assertEqual(self.flow.get_hashed_user_id(foo=None, bar=42),
                         expected)
        for value in [None, 42, '', []]:
            self.assertEqual(self.flow.get_hashed_user_id(user_id=value),
                             expected)

class LinkedInFlowTest(GoogleFlowTest):
    def create_flow(self):
        """Return a LinkedInFlow instance to use in the tests."""
        return zenith_cross.LinkedInFlow(
            'sha256', 'pepper', 'client_id', 'client_secret')

    def test_sanity(self):
        """Test the LinkedInFlow instance used in the tests."""
        self.assertIsInstance(self.flow, zenith_cross.LinkedInFlow)
        self.assertEqual(self.flow.method, 'sha256')
        self.assertEqual(self.flow.pepper, 'pepper')
        self.assertEqual(self.flow.client_id, 'client_id')
        self.assertEqual(self.flow.client_secret, 'client_secret')
        self.assertEqual(self.flow.get_name(), 'LinkedIn')
        self.assertEqual(self.flow._get_authorization_endpoint(),
                         'https://www.linkedin.com/oauth/v2/authorization')
        self.assertEqual(self.flow._get_token_endpoint(),
                         'https://www.linkedin.com/oauth/v2/accessToken')
        self.assertEqual(self.flow._get_profile_endpoint(),
                         'https://api.linkedin.com/v1/people/~?format=json')
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', 'sha256', 'pepper', 'linkedin_'))

    def assertInitialize(self, flow_class, name):
        """Test initializing a flow_class instance."""
        for value in [None, 42, [], u'fo\u00f6b\u00e4r']:
            self.assertRaises(TypeError, flow_class,
                              'sha1', value, 'client_id', 'client_secret')
            self.assertRaises(TypeError, flow_class,
                              'sha1', 'pepper', value, 'client_secret')
            self.assertRaises(TypeError, flow_class,
                              'sha1', 'pepper', 'client_id', value)
        self.assertRaises(ValueError, flow_class,
                          '', 'pepper', 'client_id', 'client_secret')
        self.assertRaises(ValueError, flow_class,
                          'foobar', 'pepper', 'client_id', 'client_secret')
        self.assertRaises(ValueError, flow_class,
                          'sha256', '', 'client_id', 'client_secret')
        self.assertRaises(ValueError, flow_class,
                          'sha256', 'pepper', '', 'client_secret')
        self.assertRaises(ValueError, flow_class,
                          'sha256', 'pepper', 'client_id', '')

        for method in hashlib.algorithms:
            for pepper in ['foobar', 'pepper']:
                flow = flow_class(method, pepper, 'bar', 'baz')
                self.assertEqual(flow.method, method)
                self.assertEqual(flow.pepper, pepper)
                self.assertEqual(flow.client_id, 'bar')
                self.assertEqual(flow.client_secret, 'baz')
                self.assertEqual(self.flow.get_name(), name)

    def test_initialize(self):
        """Test initializing a LinkedInFlow instance."""
        self.assertInitialize(zenith_cross.LinkedInFlow, 'LinkedIn')

    def test_create_login_url(self):
        """Test the URL to request a user's identity."""
        expected = self.flow._get_authorization_endpoint() + '?'
        for uri in self.redirect_uris:
            for state in ['foobar', 'state']:
                login_url = self.flow.create_login_url(uri, state)
                self.assertTrue(login_url.startswith(expected))
                self.assertIn(
                    urllib.urlencode({'client_id': self.flow.client_id}),
                    login_url)
                self.assertIn(urllib.urlencode({'redirect_uri': uri}),
                              login_url)
                self.assertIn(urllib.urlencode({'state': state}),
                              login_url)

    def test_get_access_token(self):
        """Test exchange the temporary code parameter for an access token."""
        for value in [None, 42, '', [], 'code']:
            self.assertIsNone(
                self.flow.get_access_token(value, 'redirect_uri', 'state'))

    def test_get_user_id(self):
        """Test getting the user ID."""
        for value in [None, 42, '', [], 'access_token']:
            self.assertIsNone(self.flow._get_user_id(value))

    def test_get_hashed_user_id(self):
        """Test getting the hashed user ID."""
        self.assertIsNone(self.flow.get_hashed_user_id())
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None))
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None, bar=42))
        self.assertIsNone(self.flow.get_hashed_user_id(
            access_token='access_token'))
        for value in [None, 42, '', []]:
            self.assertIsNone(self.flow.get_hashed_user_id(user_id=value))

        # Test hashing a user ID
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', self.flow.method, self.flow.pepper,
                             self.flow.get_name().lower() + '_'))

class FacebookFlowTest(LinkedInFlowTest):
    def create_flow(self):
        """Return a FacebookFlow instance to use in the tests."""
        return zenith_cross.FacebookFlow(
            'sha256', 'pepper', 'client_id', 'client_secret')

    def test_sanity(self):
        """Test the FacebookFlow instance used in the tests."""
        self.assertIsInstance(self.flow, zenith_cross.FacebookFlow)
        self.assertEqual(self.flow.method, 'sha256')
        self.assertEqual(self.flow.pepper, 'pepper')
        self.assertEqual(self.flow.client_id, 'client_id')
        self.assertEqual(self.flow.client_secret, 'client_secret')
        self.assertEqual(self.flow.get_name(), 'Facebook')
        self.assertEqual(self.flow._get_authorization_endpoint(),
                         'https://www.facebook.com/v3.0/dialog/oauth')
        self.assertEqual(self.flow._get_token_endpoint(),
                         'https://graph.facebook.com/v3.0/oauth/access_token')
        self.assertEqual(self.flow._get_profile_endpoint(),
                         'https://graph.facebook.com/v3.0/me')
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', 'sha256', 'pepper', 'facebook_'))

    def test_initialize(self):
        """Test initializing a FacebookFlow instance."""
        self.assertInitialize(zenith_cross.FacebookFlow, 'Facebook')

    def test_get_appsecret_proof(self):
        """Test the app secret proof to verify a Graph API call."""
        for token in ['foobar', 'access_token']:
            self.assertEqual(
                self.flow._get_appsecret_proof(token),
                hmac.new('client_secret', token, hashlib.sha256).hexdigest())

class GitHubFlowTest(LinkedInFlowTest):
    def create_flow(self):
        """Return a GitHubFlow instance to use in the tests."""
        return zenith_cross.GitHubFlow(
            'sha256', 'pepper', 'client_id', 'client_secret')

    def test_sanity(self):
        """Test the GitHubFlow instance used in the tests."""
        self.assertIsInstance(self.flow, zenith_cross.GitHubFlow)
        self.assertEqual(self.flow.method, 'sha256')
        self.assertEqual(self.flow.pepper, 'pepper')
        self.assertEqual(self.flow.client_id, 'client_id')
        self.assertEqual(self.flow.client_secret, 'client_secret')
        self.assertEqual(self.flow.allow_signup, 'false')
        self.assertEqual(self.flow.get_name(), 'GitHub')
        self.assertEqual(self.flow._get_authorization_endpoint(),
                         'https://github.com/login/oauth/authorize')
        self.assertEqual(self.flow._get_token_endpoint(),
                         'https://github.com/login/oauth/access_token')
        self.assertEqual(self.flow._get_profile_endpoint(),
                         'https://api.github.com/graphql')
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', 'sha256', 'pepper', 'github_'))

    def test_initialize(self):
        """Test initializing a GitHubFlow instance."""
        self.assertInitialize(zenith_cross.GitHubFlow, 'GitHub')
        for method in hashlib.algorithms:
            for pepper in ['foobar', 'pepper']:
                for value in ['on', 'yes', 'true']:
                    for signup in [value.upper(), value.title(),
                                   value.lower()]:
                        flow = zenith_cross.GitHubFlow(
                            method, pepper, 'bar', 'baz', signup)
                        self.assertEqual(flow.method, method)
                        self.assertEqual(flow.pepper, pepper)
                        self.assertEqual(flow.client_id, 'bar')
                        self.assertEqual(flow.client_secret, 'baz')
                        self.assertEqual(flow.allow_signup, 'true')
                        self.assertEqual(self.flow.get_name(), 'GitHub')
                        for uri in self.redirect_uris:
                            login_url = flow.create_login_url(uri, pepper)
                            self.assertIn(
                                urllib.urlencode({'allow_signup': 'true'}),
                                login_url)
                for value in ['off', 'no', 'false']:
                    for signup in [value.upper(), value.title(),
                                   value.lower()]:
                        flow = zenith_cross.GitHubFlow(
                            method, pepper, 'bar', 'baz', signup)
                        self.assertEqual(flow.method, method)
                        self.assertEqual(flow.pepper, pepper)
                        self.assertEqual(flow.client_id, 'bar')
                        self.assertEqual(flow.client_secret, 'baz')
                        self.assertEqual(flow.allow_signup, 'false')
                        self.assertEqual(self.flow.get_name(), 'GitHub')
                        for uri in self.redirect_uris:
                            login_url = flow.create_login_url(uri, pepper)
                            self.assertIn(
                                urllib.urlencode({'allow_signup': 'false'}),
                                login_url)

class TwitterFlowTest(LinkedInFlowTest):
    def create_flow(self):
        """Return a TwitterFlow instance to use in the tests."""
        return zenith_cross.TwitterFlow(
            'sha256', 'pepper', 'cChZNFj6T5R0TigYB9yd1w',
            'L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg')

    def test_sanity(self):
        """Test the LinkedInFlow instance used in the tests."""
        self.assertIsInstance(self.flow, zenith_cross.TwitterFlow)
        self.assertEqual(self.flow.method, 'sha256')
        self.assertEqual(self.flow.pepper, 'pepper')
        self.assertEqual(self.flow.consumer_key, 'cChZNFj6T5R0TigYB9yd1w')
        self.assertEqual(self.flow.consumer_secret,
                         'L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg')
        self.assertEqual(self.flow.get_name(), 'Twitter')
        self.assertEqual(self.flow._get_request_endpoint(),
                         'https://api.twitter.com/oauth/request_token')
        self.assertEqual(self.flow._get_authorization_endpoint(),
                         'https://api.twitter.com/oauth/authenticate')
        self.assertEqual(self.flow._get_token_endpoint(),
                         'https://api.twitter.com/oauth/access_token')
        self.assertEqual(self.flow._get_profile_endpoint(), '\
https://api.twitter.com/1.1/account/verify_credentials.json')
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', 'sha256', 'pepper', 'twitter_'))

    def test_initialize(self):
        """Test initializing a TwitterFlow instance."""
        for value in [None, 42, [], u'fo\u00f6b\u00e4r']:
            self.assertRaises(TypeError, zenith_cross.TwitterFlow,
                              'sha1', value, 'consumer_key', 'consumer_secret')
            self.assertRaises(TypeError, zenith_cross.TwitterFlow,
                              'sha1', 'pepper', value, 'consumer_secret')
            self.assertRaises(TypeError, zenith_cross.TwitterFlow,
                              'sha1', 'pepper', 'consumer_key', value)
        self.assertRaises(ValueError, zenith_cross.TwitterFlow,
                          '', 'pepper', 'consumer_key', 'consumer_secret')
        self.assertRaises(ValueError, zenith_cross.TwitterFlow,
                          'foo', 'pepper', 'consumer_key', 'consumer_secret')
        self.assertRaises(ValueError, zenith_cross.TwitterFlow,
                          'sha256', '', 'consumer_key', 'consumer_secret')
        self.assertRaises(ValueError, zenith_cross.TwitterFlow,
                          'sha256', 'pepper', '', 'consumer_secret')
        self.assertRaises(ValueError, zenith_cross.TwitterFlow,
                          'sha256', 'pepper', 'consumer_key', '')

        for method in hashlib.algorithms:
            for pepper in ['foobar', 'pepper']:
                flow = zenith_cross.TwitterFlow(method, pepper, 'bar', 'baz')
                self.assertEqual(flow.method, method)
                self.assertEqual(flow.pepper, pepper)
                self.assertEqual(flow.consumer_key, 'bar')
                self.assertEqual(flow.consumer_secret, 'baz')
                self.assertEqual(self.flow.get_name(), 'Twitter')

    def test_percent_encode(self):
        """Test Twitter percent encoding."""
        for value in [None, 42, []]:
            self.assertRaises(
                TypeError, zenith_cross.TwitterFlow._percent_encode, value)
        for value, expected in [
            ('', ''),
            ('\xe6', '%E6'),
            ('Ladies + Gentlemen', 'Ladies%20%2B%20Gentlemen'),
            ('An encoded string!', 'An%20encoded%20string%21'),
            ('Dogs, Cats & Mice', 'Dogs%2C%20Cats%20%26%20Mice'),
            (u'\u2603', '%E2%98%83'),
            ('\xe2\x98\x83', '%E2%98%83')]:
            self.assertEqual(
                zenith_cross.TwitterFlow._percent_encode(value), expected)

    def test_get_signature(self):
        """Test the signing algorithm for Twitter."""
        # Test the 2 examples in Implementing Sign in with Twitter
        self.assertEqual(self.flow._get_signature(
            'https://api.twitter.com/oauth/request_token',
            {'oauth_callback': 'http://localhost/sign-in-with-twitter/'},
            'POST', 'ea9ec8429b68d6b77cd5600adbbb0456', '1318467427'),
                         'F1Li3tvehgcraF8DMJ7OyxO4w9Y=')
        self.assertEqual(self.flow._get_signature(
            'https://api.twitter.com/oauth/access_token',
            {'oauth_verifier': 'uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY'},
            'POST', 'a9900fe68e2573b27a37f10fbad6a755', '1318467427',
            'NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0',
            'veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI'),
                         '39cipBtIOHEEnybAR4sATQTpl2I=')

        # Test the example in the Creating a signature guide
        self.flow.consumer_key = 'xvz1evFS4wEEPTGEFPHBog'
        self.flow.consumer_secret = '\
kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw'
        self.assertEqual(self.flow._get_signature(
            'https://api.twitter.com/1.1/statuses/update.json',
            {'status': 'Hello Ladies + Gentlemen, a signed OAuth request!',
             'include_entities': 'true'}, 'POST',
            'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', '1318622958',
            token='370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
            token_secret='LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE'),
                         'hCtSmYh+iHYCEqBWrE7C7hYmtUk=')

    def test_get_authorization_header(self):
        """Test building the authorization header for Twitter."""
        # Test the 2 examples in Implementing Sign in with Twitter
        self.assertEqual(self.flow._get_authorization_header(
            'ea9ec8429b68d6b77cd5600adbbb0456', 'F1Li3tvehgcraF8DMJ7OyxO4w9Y=',
            '1318467427', 'http://localhost/sign-in-with-twitter/'), 'OAuth \
oauth_callback="http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F", \
oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w", \
oauth_nonce="ea9ec8429b68d6b77cd5600adbbb0456", \
oauth_signature="F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D", \
oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318467427", \
oauth_version="1.0"')
        self.assertEqual(self.flow._get_authorization_header(
            'a9900fe68e2573b27a37f10fbad6a755', '39cipBtIOHEEnybAR4sATQTpl2I=',
            '1318467427', '', 'NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0'),
                         'OAuth \
oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w", \
oauth_nonce="a9900fe68e2573b27a37f10fbad6a755", \
oauth_signature="39cipBtIOHEEnybAR4sATQTpl2I%3D", \
oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318467427", \
oauth_token="NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0", \
oauth_version="1.0"')

        # Test the example in the POST oauth/request_token reference
        self.flow.consumer_key = 'OqEqJeafRSF11jBMStrZz'
        self.assertEqual(self.flow._get_authorization_header(
            'K7ny27JTpKVsTgdyLdDfmQQWVLERj2zAK5BslRsqyw',
            'Pc+MLdv028fxCErFyi8KXFM+ddU=', '1300228849',
            callback='http://myapp.com:3005/twitter/process_callback'),
                         'OAuth \
oauth_callback="http%3A%2F%2Fmyapp.com%3A3005%2Ftwitter%2Fprocess_callback", \
oauth_consumer_key="OqEqJeafRSF11jBMStrZz", \
oauth_nonce="K7ny27JTpKVsTgdyLdDfmQQWVLERj2zAK5BslRsqyw", \
oauth_signature="Pc%2BMLdv028fxCErFyi8KXFM%2BddU%3D", \
oauth_signature_method="HMAC-SHA1", oauth_timestamp="1300228849", \
oauth_version="1.0"')

        # Test the example in the Authorizing a request guide
        self.flow.consumer_key = 'xvz1evFS4wEEPTGEFPHBog'
        self.assertEqual(self.flow._get_authorization_header(
            'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
            'tnnArxj06cWHq44gCs1OSKk/jLY=', '1318622958',
            token='370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb'),
                         'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", \
oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", \
oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", \
oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", \
oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", \
oauth_version="1.0"')

    def test_twitter_fetch(self):
        """Test making a HTTP request to Twitter with OAuth 1.0a."""
        for value in [None, 42, []]:
            self.assertRaises(TypeError, self.flow._twitter_fetch,
                              value, {}, 'GET')
            self.assertRaises(TypeError, self.flow._twitter_fetch,
                              'http://example.com', value, 'POST')
            self.assertRaises(TypeError, self.flow._twitter_fetch,
                              'http://example.com', {}, value)
        self.assertRaises(ValueError, self.flow._twitter_fetch, '', {}, 'POST')
        for value in ['', 'HEAD', 'PUT', 'DELETE', 'PATCH']:
            self.assertRaises(ValueError, self.flow._twitter_fetch,
                              'http://example.com', {}, value)

    def test_create_login_url(self):
        """Test the URL to request a user's Twitter identity."""
        for uri in self.redirect_uris:
            for state in ['foobar', 'state']:
                self.assertEqual(self.flow.create_login_url(uri, state),
                                 (None, None, None))

    def test_get_access_token(self):
        """Test trading the request token for an access token."""
        for value in [None, 42, '', []]:
            self.assertEqual(self.flow.get_access_token(
                value, 'secret', 'verifier'), (None, None))
            self.assertEqual(self.flow.get_access_token(
                'token', value, 'verifier'), (None, None))
            self.assertEqual(self.flow.get_access_token(
                'token', 'secret', value), (None, None))
        self.assertEqual(self.flow.get_access_token(
            'token', 'secret', 'verifier'), (None, None))

    def test_get_user_id(self):
        """Test getting the Twitter user ID using an access token."""
        for value in [None, 42, '', []]:
            self.assertIsNone(self.flow._get_user_id(value, 'secret'))
            self.assertIsNone(self.flow._get_user_id('token', value))
        self.assertIsNone(self.flow._get_user_id('token', 'secret'))

    def test_get_hashed_user_id(self):
        """Test getting the hashed Twitter user ID."""
        self.assertIsNone(self.flow.get_hashed_user_id())
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None))
        self.assertIsNone(self.flow.get_hashed_user_id(foo=None, bar=42))
        self.assertIsNone(self.flow.get_hashed_user_id(
            token='token', secret='secret'))
        for value in [None, 42, '', []]:
            self.assertIsNone(self.flow.get_hashed_user_id(user_id=value))

        # Test hashing a user ID
        self.assertEqual(self.flow.get_hashed_user_id(user_id='foobar'),
                         zenith_cross._hash_user_id(
                             'foobar', self.flow.method, self.flow.pepper,
                             self.flow.get_name().lower() + '_'))
