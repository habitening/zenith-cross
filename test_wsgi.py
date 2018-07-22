"""Test the WSGI application using WebTest.

These tests require the WebTest package.

The easiest way is to install it in a virtualenv environment and then run
these tests through the python interpreter in that environment.
"""

import webapp2
from webapp2_extras import securecookie
import webtest

import main
import models
import test
import zenith_cross

class _WSGITestCase(test.BaseTestCase):

    """Extend BaseTestCase to test the WSGI application."""

    def setUp(self):
        super(_WSGITestCase, self).setUp()

        # Wrap the WSGI application in a TestApp
        self.app = webtest.TestApp(main.app)

        self.serializer = securecookie.SecureCookieSerializer(
            main.app.config['webapp2_extras.sessions']['secret_key'])
        """Serializer to serialize and deserialize cookie values."""

    def get_session_ID(self, value, name='session'):
        """Return the session ID encoded in the cookie value."""
        data = self.serializer.deserialize(name, value, max_age=None)
        return data.get('_sid')

    def set_session_ID(self, sid, name='session'):
        """Return a string cookie value encoding the session ID sid."""
        value = self.serializer.serialize(name, {'_sid': sid})
        self.app.set_cookie(name, value)
        return value

    def uri_for(self, name, *args, **kwargs):
        """Return the URI for a route named name."""
        # Create a blank request for its host and scheme
        request = webapp2.Request.blank('/')
        request.app = main.app
        return webapp2.uri_for(name, _request=request, *args, **kwargs)

class SanityTest(_WSGITestCase):

    """Test the test fixtures."""

    def test_get_session_ID(self):
        """Test deserializing the session ID from a secure cookie."""
        for sid in ['foobar', 'baz']:
            value = self.serializer.serialize('session', {'_sid': sid})
            self.assertEqual(self.get_session_ID(value), sid)
            self.assertEqual(self.get_session_ID(value, 'session'), sid)
            self.assertRaises(AttributeError, self.get_session_ID,
                              value, 'sessionid')
            value = self.serializer.serialize('sessionid', {'_sid': sid})
            self.assertEqual(self.get_session_ID(value, 'sessionid'), sid)
            self.assertRaises(AttributeError, self.get_session_ID, value)
            self.assertRaises(AttributeError, self.get_session_ID,
                              value, 'session')

    def test_set_session_ID(self):
        """Test serializing the session ID to a cookie value."""
        for sid in ['foobar', 'baz']:
            expected = self.serializer.serialize('session', {'_sid': sid})
            self.assertEqual(self.set_session_ID(sid), expected)
            self.assertEqual(self.app.cookies,
                             {'session': '"' + expected + '"'})
            self.app.reset()
            self.assertEqual(self.set_session_ID(sid, 'session'), expected)
            self.assertEqual(self.app.cookies,
                             {'session': '"' + expected + '"'})
            self.app.reset()
            expected = self.serializer.serialize('sessionid', {'_sid': sid})
            self.assertEqual(self.set_session_ID(sid, 'sessionid'), expected)
            self.assertEqual(self.app.cookies,
                             {'sessionid': '"' + expected + '"'})
            self.app.reset()

    def test_uri_for(self):
        """Test getting the URI for a named route."""
        for value, expected in [
            ('home', '/'),
            ('secret', '/secret/'),
            ('private', '/private/')]:
            self.assertEqual(self.uri_for(value), expected)

class LoginTest(_WSGITestCase):
    def setUp(self):
        super(LoginTest, self).setUp()

        self.url = self.uri_for('login')
        """String URL for the login route."""

        self.provider_map = {
            'facebook': self.url,
            'github': 'https://github.com/login/oauth/authorize',
            'google': 'https://www.google.com/accounts/Login',
            'linkedin': self.url,
            'twitter': self.url
        }
        """Dictionary mapping an identity provider to its login URL."""

        self.assertEqual(models.JSONSession.query().count(), 0)

    def test_bad_methods(self):
        """Test incorrect request methods."""
        response = self.app.put(self.url, status=405)
        self.assertEqual(response.status_int, 405)
        self.assertEqual(models.JSONSession.query().count(), 0)

        response = self.app.delete(self.url, status=405)
        self.assertEqual(response.status_int, 405)
        self.assertEqual(models.JSONSession.query().count(), 0)

    def test_login(self):
        """Test the login page."""
        response = self.app.get(self.url)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(models.JSONSession.query().count(), 0)
        response = response.form.submit()
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.url))
        self.assertNotIn('Set-Cookie', response.headers)

        for provider, redirect in self.provider_map.iteritems():
            response = self.app.get(self.url)
            self.assertEqual(response.status_int, 200)
            self.assertEqual(models.JSONSession.query().count(), 0)
            response = response.form.submit('provider:' + provider)
            self.assertEqual(response.status_int, 302)
            if not redirect.startswith('https'):
                self.assertTrue(response.location.endswith(redirect))
                self.assertNotIn('Set-Cookie', response.headers)
                continue

            self.assertTrue(response.location.startswith(redirect))
            self.assertIn('Set-Cookie', response.headers)
            self.assertTrue(
                response.headers['Set-Cookie'].startswith('session='))
            cookie_map = self.app.cookies
            self.assertEqual(len(cookie_map), 1)
            self.assertIn('session', cookie_map)

            self.assertEqual(models.JSONSession.query().count(), 1)
            session = models.JSONSession.query().get()
            self.assertEqual(session.key.string_id(),
                             self.get_session_ID(cookie_map['session']))
            self.assertEqual(len(session.data), 1)
            self.assertIn('state', session.data)

            # Reset for the next iteration
            self.app.reset()
            session.key.delete()

    def test_post(self):
        """Test the POST method directly."""
        response = self.app.post(self.url)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.url))
        self.assertNotIn('Set-Cookie', response.headers)

        for provider, redirect in self.provider_map.iteritems():
            self.assertEqual(models.JSONSession.query().count(), 0)
            response = self.app.post(
                self.url, {'provider:' + provider: provider})
            self.assertEqual(response.status_int, 302)
            if not redirect.startswith('https'):
                self.assertTrue(response.location.endswith(redirect))
                self.assertNotIn('Set-Cookie', response.headers)
                continue

            self.assertTrue(response.location.startswith(redirect))
            self.assertIn('Set-Cookie', response.headers)
            self.assertTrue(
                response.headers['Set-Cookie'].startswith('session='))
            cookie_map = self.app.cookies
            self.assertEqual(len(cookie_map), 1)
            self.assertIn('session', cookie_map)

            self.assertEqual(models.JSONSession.query().count(), 1)
            session = models.JSONSession.query().get()
            self.assertEqual(session.key.string_id(),
                             self.get_session_ID(cookie_map['session']))
            self.assertEqual(len(session.data), 1)
            self.assertIn('state', session.data)

            # Reset for the next iteration
            self.app.reset()
            session.key.delete()

class _CallbackTestCase(_WSGITestCase):
    def setUp(self):
        super(_CallbackTestCase, self).setUp()

        self.url = self.get_self_url()
        """String URL for the route being tested."""

        self.after_logout = self.uri_for('home')
        """String URL for the route after logging out or when login fails."""

        self.assertEqual(models.JSONSession.query().count(), 0)

    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('github_callback')

    def test_strict_slash(self):
        """Test there is no slash at the end of the URL."""
        self.assertFalse(self.url.endswith('/'))
        response = self.app.get(self.url + '/', status=404)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(models.JSONSession.query().count(), 0)

    def test_bad_methods(self):
        """Test incorrect request methods."""
        response = self.app.post(self.url, status=405)
        self.assertEqual(response.status_int, 405)
        self.assertEqual(models.JSONSession.query().count(), 0)

        response = self.app.put(self.url, status=405)
        self.assertEqual(response.status_int, 405)
        self.assertEqual(models.JSONSession.query().count(), 0)

        response = self.app.delete(self.url, status=405)
        self.assertEqual(response.status_int, 405)
        self.assertEqual(models.JSONSession.query().count(), 0)

    def test_no_login(self):
        """Test when the user did not login."""
        response = self.app.get(self.url)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.after_logout))
        self.assertNotIn('Set-Cookie', response.headers)

class LogoutTest(_CallbackTestCase):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('logout')

    def test_no_login(self):
        """Test logging out without logging in first."""
        response = self.app.get(self.url)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.after_logout))
        # Test the cookie is marked for deletion
        self.assertIn('Set-Cookie', response.headers)
        self.assertTrue(
            response.headers['Set-Cookie'].startswith('session=; Max-Age=0;'))

    def test_login(self):
        """Test logging out when logged in."""
        session = models.JSONSession._create({
            'hash': 'foo',
            'state': 'bar'
        })
        self.set_session_ID(session.key.string_id())
        self.assertEqual(models.JSONSession.query().count(), 1)
        response = self.app.get(self.url)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertIsNone(session.key.get())
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.after_logout))
        # Test the cookie is marked for deletion
        self.assertIn('Set-Cookie', response.headers)
        self.assertTrue(
            response.headers['Set-Cookie'].startswith('session=; Max-Age=0;'))

class GoogleTest(_CallbackTestCase):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('google_callback')

    def test_login(self):
        """Test when the user did login."""
        # Simulate a login in the testbed
        self.testbed.setup_env(
            USER_ID='test', USER_EMAIL='test@example.com', overwrite=True)
        response = self.app.get(self.url)
        self.assertEqual(models.JSONSession.query().count(), 1)
        flow = zenith_cross._PROVIDER_MAP.get('Google')
        expected_hash = flow.get_hashed_user_id(user_id='test')
        session = models.JSONSession.query().get()
        self.assertEqual(session.data, {
            'hash': expected_hash
        })
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(self.uri_for('private')))
        self.assertIn('Set-Cookie', response.headers)
        self.assertTrue(response.headers['Set-Cookie'].startswith('session='))
        cookie_map = self.app.cookies
        self.assertEqual(len(cookie_map), 1)
        self.assertIn('session', cookie_map)
        self.assertEqual(session.key.string_id(),
                         self.get_session_ID(cookie_map['session']))

        # Test the private page is visible because we are logged in
        # Need to force TestApp to send the session cookie
        self.set_session_ID(session.key.string_id())
        response = response.follow()
        self.assertEqual(models.JSONSession.query().count(), 1)
        self.assertEqual(response.status_int, 200)
        self.assertIn('<dd>{0}</dd>'.format(expected_hash), response.body)
        cookie_map = self.app.cookies
        self.assertEqual(len(cookie_map), 1)
        self.assertIn('session', cookie_map)
        self.assertEqual(session.key.string_id(),
                         self.get_session_ID(cookie_map['session']))

class LinkedInTest(_CallbackTestCase):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('linkedin_callback')

    def test_error(self):
        """Test when there is an error with the login."""
        for params in [
            {'error': 'error'},
            {'error_description': 'Login error'},
            {'error': 'error',
             'error_description': 'Login error'}]:
            response = self.app.get(self.url, params)
            self.assertEqual(models.JSONSession.query().count(), 0)
            self.assertEqual(response.status_int, 302)
            self.assertTrue(response.location.endswith(self.after_logout))
            self.assertNotIn('Set-Cookie', response.headers)

    def test_bad_state(self):
        """Test when the state is incorrect."""
        session = models.JSONSession._create({'state': 'foobar'})
        for params in [
            {},
            {'state': ''},
            {'state': 'bar'},
            {'state': 'baz'},
            # Test an invalid temporary authorization code parameter
            {'state': 'foobar', 'code': ''}]:
            self.set_session_ID(session.key.string_id())
            response = self.app.get(self.url, params)
            # The session is not deleted because the correct callback may come
            self.assertEqual(models.JSONSession.query().count(), 1)
            self.assertEqual(response.status_int, 302)
            self.assertTrue(response.location.endswith(self.after_logout))
            self.assertNotIn('Set-Cookie', response.headers)

class FacebookTest(LinkedInTest):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('facebook_callback')

    def test_error(self):
        """Test when there is an error with the login."""
        super(FacebookTest, self).test_error()
        for params in [
            {'error_reason': 'Error reason'},
            {'error': 'error',
             'error_description': 'Login error',
             'error_reason': 'Error reason'}]:
            response = self.app.get(self.url, params)
            self.assertEqual(models.JSONSession.query().count(), 0)
            self.assertEqual(response.status_int, 302)
            self.assertTrue(response.location.endswith(self.after_logout))
            self.assertNotIn('Set-Cookie', response.headers)

class GitHubTest(LinkedInTest):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('github_callback')

class TwitterTest(LinkedInTest):
    def get_self_url(self):
        """Return the string URL for the route being tested."""
        return self.uri_for('twitter_callback')

    def test_bad_state(self):
        """Test when the oauth_token is incorrect."""
        session = models.JSONSession._create({'oauth_token': 'foobar'})
        for params in [
            {},
            {'oauth_token': ''},
            {'oauth_token': 'bar'},
            {'oauth_token': 'baz'},
            # Test an invalid oauth_verifier
            {'oauth_token': 'foobar', 'oauth_verifier': ''}]:
            self.set_session_ID(session.key.string_id())
            response = self.app.get(self.url, params)
            # The session is not deleted because the correct callback may come
            self.assertEqual(models.JSONSession.query().count(), 1)
            self.assertEqual(response.status_int, 302)
            self.assertTrue(response.location.endswith(self.after_logout))
            self.assertNotIn('Set-Cookie', response.headers)

class FrontendTest(_WSGITestCase):
    def test_home(self):
        """Test the home page."""
        response = self.app.get(self.uri_for('home'))
        self.assertEqual(response.status_int, 200)
        self.assertIn('zenith-cross', response.body)

    def test_secret(self):
        """Test the secret keys page."""
        response = self.app.get(self.uri_for('secret'))
        self.assertEqual(response.status_int, 200)
        self.assertIn('<h1>Secret keys</h1>', response.body)
        self.assertIn('<h2>Alphanumeric keys</h2>', response.body)
        self.assertIn('<h2>ASCII printable keys</h2>', response.body)
        for pre_section in response.html.find_all('pre'):
            self.assertGreater(len(pre_section), 0)

    def test_private(self):
        """Test the private page."""
        url = self.uri_for('private')
        login_url = self.uri_for('login')

        # Test without logging in the page redirects to login
        response = self.app.get(url)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(login_url))

        # Simulate logging in with a session
        session = models.JSONSession._create({
            'hash': 'foo',
            'state': 'bar'
        })
        self.set_session_ID(session.key.string_id())
        response = self.app.get(url)
        self.assertEqual(response.status_int, 200)
        self.assertIn('<dd>foo</dd>', response.body)
        self.assertIn('<dd>bar</dd>', response.body)

        # Test missing "hash" key is the same as not logged in
        session.data = {
            'state': 'bar'
        }
        session.put()
        response = self.app.get(url)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(login_url))

        session.key.delete()
        response = self.app.get(url)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(login_url))

        self.app.reset()
        response = self.app.get(url)
        self.assertEqual(response.status_int, 302)
        self.assertTrue(response.location.endswith(login_url))

    def test_private_multiple_sessions(self):
        """Test the private page with multiple different sessions."""
        sessions = [
            models.JSONSession._create({
                'hash': 'foo',
                'state': 'bar'
            }),
            models.JSONSession._create({
                'hash': 'tic',
                'state': 'tac',
                'user_id': 'toe'
            }),
            models.JSONSession._create({
                'hash': 'Rock',
                'state': 'Paper',
                'user_id': 'Scissors'
            })]
        for session in sessions:
            self.set_session_ID(session.key.string_id())
            response = self.app.get(self.uri_for('private'))
            self.assertEqual(response.status_int, 200)
            for key, value in session.data.iteritems():
                if key != 'user_id':
                    self.assertIn('<dd>{0}</dd>'.format(value), response.body)
            # Test none of the other sessions leaked through
            for s in sessions:
                if s.key.string_id() == session.key.string_id():
                    continue
                for key, value in s.data.iteritems():
                    self.assertNotIn('<dd>{0}</dd>'.format(value),
                                     response.body)
