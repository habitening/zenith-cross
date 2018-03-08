"""Test the models."""

from webapp2_extras import security
from webapp2_extras import sessions

import models
import test

class JSONSessionTest(test.BaseTestCase):
    def test_string_methods(self):
        """Test the __str__ and __unicode__ methods."""
        for sid in ['42', 'foobar']:
            expected = '<JSONSession ' + sid + '>'
            session = models.JSONSession(id=sid)
            self.assertEqual(str(session), expected)
            # unicode() calls __str__
            self.assertEqual(unicode(session), expected)

    def test_create(self):
        """Test creating JSONSession entities."""
        self.assertEqual(models.JSONSession.query().count(), 0)
        empty_session = models.JSONSession._create({})
        self.assertEqual(models.JSONSession.query().count(), 1)
        self.assertEqual(empty_session.data, {})
        self.assertLessEqual(empty_session.created, empty_session.modified)

        foobar_session = models.JSONSession._create({'foo': 'bar'})
        self.assertEqual(models.JSONSession.query().count(), 2)
        self.assertEqual(foobar_session.data, {'foo': 'bar'})
        self.assertLessEqual(foobar_session.created, foobar_session.modified)
        self.assertNotEqual(empty_session.key.string_id(),
                            foobar_session.key.string_id())

        empty_session.data = {'bar': 'baz'}
        empty_session.put()
        self.assertEqual(models.JSONSession.query().count(), 2)
        self.assertLess(empty_session.created, empty_session.modified)

    def test_delete_created_before(self):
        """Test deleting JSONSession entities created prior to a datetime."""
        self.test_create()
        sessions = models.JSONSession.query().fetch()
        self.assertEqual(len(sessions), 2)
        sessions.sort(key=lambda s: s.created)

        models.JSONSession.delete_created_before(sessions[-1].created)
        self.assertEqual(models.JSONSession.query().count(), 1)
        self.assertIsNone(sessions[0].key.get())
        self.assertIsInstance(sessions[1].key.get(), models.JSONSession)

    def test_delete_modified_before(self):
        """Test deleting JSONSession entities modified prior to a datetime."""
        self.test_create()
        sessions = models.JSONSession.query().fetch()
        self.assertEqual(len(sessions), 2)
        sessions.sort(key=lambda s: s.modified)

        models.JSONSession.delete_modified_before(sessions[-1].modified)
        self.assertEqual(models.JSONSession.query().count(), 1)
        self.assertIsNone(sessions[0].key.get())
        self.assertIsInstance(sessions[1].key.get(), models.JSONSession)

    def test_get_new_sid(self):
        """Test generating new session IDs."""
        for i in xrange(5):
            sid = models.JSONSession._get_new_sid()
            self.assertIsInstance(sid, str)
            self.assertEqual(len(sid), 128)
            for c in sid:
                self.assertIn(c, security.ALPHANUMERIC)

    def test_is_valid_sid(self):
        """Test if a session ID is valid."""
        for value in [None, 42, '', [], 'foobar', u'fo\u00f6b\u00e4r']:
            self.assertFalse(models.JSONSession._is_valid_sid(value))
        expected = 'a' * 128
        self.assertTrue(models.JSONSession._is_valid_sid(expected))
        for value in ['@' + expected[1:], expected[:-1] + '@']:
            self.assertFalse(models.JSONSession._is_valid_sid(value))

class DummyResponse(object):

    """Fake response object to use in the tests."""

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset the counts."""
        self.set_cookie_count = 0
        """Integer number of times set_cookie() is called."""

        self.delete_cookie_count = 0
        """Integer number of times delete_cookie() is called."""

    def set_cookie(self, *args, **kwargs):
        """Increment the count times this method is called."""
        self.set_cookie_count += 1

    def delete_cookie(self, *args, **kwargs):
        """Increment the count times this method is called."""
        self.delete_cookie_count += 1

class DummyStore(object):

    """Fake SessionStore object to use in the tests."""

    def __init__(self, sid=None):
        self.config = {'cookie_args': {}}
        """Dummy configuration dictionary."""

        self.sid = sid
        """String session ID to return."""

    def get_secure_cookie(self, name, max_age=None):
        """Return a dictionary with self.sid keyed under "_sid"."""
        return {'_sid': self.sid}

    def save_secure_cookie(self, response, name, value, **kwargs):
        """Call response.set_cookie() with the arguments."""
        response.set_cookie(name, value, **kwargs)

class JSONSessionFactoryTest(test.BaseTestCase):
    def test_get_session(self):
        """Test looking up the session from a secure cookie."""
        factory = models.JSONSessionFactory('factory', DummyStore())
        self.assertEqual(models.JSONSession.query().count(), 0)
        session = factory.get_session()
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertIsInstance(session, sessions.SessionDict)
        self.assertTrue(session.new)
        self.assertFalse(session.modified)
        self.assertEqual(dict(session), {})
        session['foo'] = 'bar'
        self.assertTrue(session.new)
        self.assertTrue(session.modified)
        self.assertEqual(dict(session), {'foo': 'bar'})
        self.assertEqual(dict(session), dict(factory.get_session()))

        # Test a new SessionDict is returned for an invalid session ID
        for value in [None, 42, '', [], 'foobar', u'fo\u00f6b\u00e4r']:
            factory = models.JSONSessionFactory('factory', DummyStore(value))
            self.assertEqual(models.JSONSession.query().count(), 0)
            session = factory.get_session()
            self.assertEqual(models.JSONSession.query().count(), 0)
            self.assertIsInstance(session, sessions.SessionDict)
            self.assertTrue(session.new)
            self.assertFalse(session.modified)
            self.assertEqual(dict(session), {})
            session['foo'] = 'bar'
            self.assertTrue(session.new)
            self.assertTrue(session.modified)
            self.assertEqual(dict(session), {'foo': 'bar'})
            self.assertEqual(dict(session), dict(factory.get_session()))

        foobar_session = models.JSONSession._create({'foo': 'bar'})
        factory = models.JSONSessionFactory(
            'factory', DummyStore(foobar_session.key.string_id()))
        self.assertEqual(models.JSONSession.query().count(), 1)
        session = factory.get_session()
        self.assertEqual(models.JSONSession.query().count(), 1)
        self.assertIsInstance(session, sessions.SessionDict)
        self.assertFalse(session.new)
        self.assertFalse(session.modified)
        self.assertEqual(dict(session), foobar_session.data)

        # Test when the session is not found in the datastore
        foobar_session.key.delete()
        factory.session = None
        self.assertEqual(models.JSONSession.query().count(), 0)
        session = factory.get_session()
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertIsInstance(session, sessions.SessionDict)
        self.assertTrue(session.new)
        self.assertFalse(session.modified)
        self.assertEqual(dict(session), {})

    def test_get_by_sid(self):
        """Test getting a SessionDict object for a session ID."""
        factory = models.JSONSessionFactory('factory', DummyStore())
        # Test a new SessionDict is returned for an invalid session ID
        for value in [None, 42, '', [], 'foobar', u'fo\u00f6b\u00e4r']:
            factory.sid = 'session'
            session = factory._get_by_sid(value)
            self.assertIsNone(factory.sid)
            self.assertIsInstance(session, sessions.SessionDict)
            self.assertTrue(session.new)
            self.assertFalse(session.modified)
            self.assertEqual(dict(session), {})

        foobar_session = models.JSONSession._create({'foo': 'bar'})
        session = factory._get_by_sid(foobar_session.key.string_id())
        self.assertEqual(factory.sid, foobar_session.key.string_id())
        self.assertIsInstance(session, sessions.SessionDict)
        self.assertFalse(session.new)
        self.assertFalse(session.modified)
        self.assertEqual(dict(session), foobar_session.data)

        # Test when the session is not found in the datastore
        foobar_session.key.delete()
        session = factory._get_by_sid(foobar_session.key.string_id())
        self.assertIsNone(factory.sid)
        self.assertIsInstance(session, sessions.SessionDict)
        self.assertTrue(session.new)
        self.assertFalse(session.modified)
        self.assertEqual(dict(session), {})

    def test_is_valid_sid(self):
        """Test _is_valid_sid() should not be called."""
        factory = models.JSONSessionFactory('factory', DummyStore())
        for value in [None, 42, '', [], 'foobar', u'fo\u00f6b\u00e4r']:
            self.assertRaises(DeprecationWarning, factory._is_valid_sid, value)

    def test_get_new_sid(self):
        """Test _get_new_sid() should not be called."""
        factory = models.JSONSessionFactory('factory', DummyStore())
        self.assertRaises(DeprecationWarning, factory._get_new_sid)

    def test_save_session(self):
        """Test saving the session to the datastore.

        There are 8 cases to consider based on the session ID, session.new,
        and session.modified:
        self.sid new   modified Expected
        invalid  False False    Do nothing
            (This case is impossible in practice because invalid session ID
             always returns a new empty SessionDict.)
        invalid  False True     Create a new JSONSession to store the session
            (This case is impossible in practice because invalid session ID
             always returns a new empty SessionDict.)
        invalid  True  False    Do nothing
        invalid  True  True     Create a new JSONSession to store the session
        valid    False False    Do nothing
        valid    False True     Update the existing JSONSession in datastore
        valid    True  False    Do nothing
            (This case is impossible in practice because a valid session ID
             not found in the datastore resets the session ID.)
        valid    True  True     Create a new JSONSession to store the session
            (This case is impossible in practice because a valid session ID
             not found in the datastore resets the session ID.)
        """
        factory = models.JSONSessionFactory('factory', DummyStore())
        response = DummyResponse()
        for value in [None, 42, '', []]:
            factory.session = value
            factory.save_session(response)
            self.assertEqual(models.JSONSession.query().count(), 0)
            self.assertEqual(response.set_cookie_count, 0)
            self.assertEqual(response.delete_cookie_count, 0)

        # Test when the session ID is invalid and SessionDict is not new
        factory.sid = None
        factory.session = sessions.SessionDict(factory)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 0)
        factory.session['foo'] = 'bar'
        self.assertIsNone(factory.sid)
        self.assertFalse(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'foo': 'bar'})
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 1)
        session = models.JSONSession.query().get()
        self.assertEqual(session.data, {'foo': 'bar'})
        self.assertEqual(response.set_cookie_count, 1)
        self.assertEqual(response.delete_cookie_count, 0)
        session.key.delete()
        self.assertEqual(models.JSONSession.query().count(), 0)

        # Test when the session ID is invalid and SessionDict is new
        response.reset()
        factory.sid = None
        factory.session = sessions.SessionDict(factory, new=True)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 0)
        factory.session['foo'] = 'bar'
        self.assertIsNone(factory.sid)
        self.assertTrue(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'foo': 'bar'})
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 1)
        sid = session.key.string_id()
        session = models.JSONSession.query().get()
        self.assertNotEqual(session.key.string_id(), sid)
        self.assertEqual(session.data, {'foo': 'bar'})
        self.assertEqual(response.set_cookie_count, 1)
        self.assertEqual(response.delete_cookie_count, 0)

        # Test when the session ID is valid and SessionDict is not new
        response.reset()
        sid = session.key.string_id()
        self.assertEqual(factory.sid, sid)
        factory.session = sessions.SessionDict(factory)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 1)
        session = models.JSONSession.query().get()
        self.assertEqual(session.key.string_id(), sid)
        self.assertEqual(session.data, {'foo': 'bar'})
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 0)
        factory.session['foo'] = 'baz'
        self.assertEqual(factory.sid, sid)
        self.assertFalse(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'foo': 'baz'})
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 1)
        session = models.JSONSession.query().get()
        self.assertEqual(session.key.string_id(), sid)
        self.assertEqual(session.data, {'foo': 'baz'})
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 0)

        # Test when the session ID is valid and SessionDict is new
        self.assertEqual(factory.sid, sid)
        factory.session = sessions.SessionDict(factory, new=True)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 1)
        session = models.JSONSession.query().get()
        self.assertEqual(session.key.string_id(), sid)
        self.assertEqual(session.data, {'foo': 'baz'})
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 0)
        factory.session['foo'] = 'bar'
        self.assertEqual(factory.sid, sid)
        self.assertTrue(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'foo': 'bar'})
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 2)
        self.assertEqual(factory.sid, sid)
        for session in models.JSONSession.query().fetch():
            if session.data['foo'] == 'bar':
                self.assertEqual(session.key.string_id(), sid)
            elif session.data['foo'] == 'baz':
                self.assertNotEqual(session.key.string_id(), sid)
                self.assertNotEqual(session.key.string_id(), factory.sid)
            else:
                self.fail('Unexpected JSONSession in datastore.')
        self.assertEqual(response.set_cookie_count, 1)
        self.assertEqual(response.delete_cookie_count, 0)

    def test_save_session_logout(self):
        """Test saving the session with the special "_logout" key."""
        factory = models.JSONSessionFactory('factory', DummyStore())
        response = DummyResponse()

        # Test "_logout" without a JSONSession in datastore
        factory.session = sessions.SessionDict(factory, new=True)
        factory.session['_logout'] = True
        self.assertIsNone(factory.sid)
        self.assertTrue(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'_logout': True})
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 1)

        # Test "_logout" with a JSONSession in datastore
        response.reset()
        foobar_session = models.JSONSession._create({'foo': 'bar'})
        factory.session = factory._get_by_sid(foobar_session.key.string_id())
        factory.session['_logout'] = True
        self.assertEqual(factory.sid, foobar_session.key.string_id())
        self.assertFalse(factory.session.new)
        self.assertTrue(factory.session.modified)
        self.assertEqual(dict(factory.session), {'foo': 'bar',
                                                 '_logout': True})
        self.assertEqual(models.JSONSession.query().count(), 1)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 1)

        # Test "_logout" accidentally saved to datastore
        # This is not possible in the normal flow
        response.reset()
        logout_session = models.JSONSession._create({'_logout': True})
        factory.session = factory._get_by_sid(logout_session.key.string_id())
        self.assertEqual(factory.sid, logout_session.key.string_id())
        self.assertFalse(factory.session.new)
        self.assertFalse(factory.session.modified)
        self.assertEqual(dict(factory.session), {'_logout': True})
        self.assertEqual(models.JSONSession.query().count(), 1)
        factory.save_session(response)
        self.assertEqual(models.JSONSession.query().count(), 0)
        self.assertEqual(response.set_cookie_count, 0)
        self.assertEqual(response.delete_cookie_count, 1)
