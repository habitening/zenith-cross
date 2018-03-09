"""The models."""

import datetime

from google.appengine.ext import ndb

from webapp2_extras import security
from webapp2_extras import sessions

class JSONSession(ndb.Model):

    """Model to store session data in a JSON property.

    This class is similar to the Session entity model class in
    webapp2_extras.appengine.sessions_ndb with the following differences:
        session data is stored as JSON instead of pickling because text
            serialization is superior (human readable and more portable) to
            binary serialization
        unnecessary memcache calls are removed because NDB already caches
            entities in memcache and caching more items in memcache just
            increases the chance of eviction
        get_by_sid() is removed because get_by_id() already does the same thing
        create the entity in a transaction to make sure the ID is unique and
            to avoid session fixation

    JSON limits the type of session data we can accept to dict, list, string,
    int, long, float, True, False, or None. If these are not enough, then you
    are probably doing something too complicated. I humbly suggest you factor
    the complication out to an entity model class and simply store the key in
    the session.
    """

    data = ndb.JsonProperty(default=None, indexed=False)
    """Dictionary session data stored as JSON."""

    modified = ndb.DateTimeProperty(auto_now=True, indexed=True)
    """DateTime when the session was last modified."""

    created = ndb.DateTimeProperty(auto_now_add=True, indexed=True)
    """DateTime when the session was created."""

    def __str__(self):
        return '<JSONSession ' + self.key.string_id().encode(
            'ascii', 'ignore') + '>'

    @classmethod
    @ndb.transactional
    def _create(cls, data):
        """Return a new JSONSession entity with a unique ID.

        Even though the chance of a duplicate ID being generated is very small,
        it is not 0. Since the session is used for authentication, we don't
        want to accidentally reuse the same ID leading to session fixation.
        Fortunately, the tiny chance of a duplicate means the checking loop
        is unlikely to run more than a few iterations.

        Args:
            data: Dictionary session data.
        Returns:
            JSONSession entity saved to the datastore with a unique ID.
        """
        while True:
            sid = cls._get_new_sid()
            backing = cls.get_by_id(sid)
            if not isinstance(backing, cls):
                # There is no JSONSession entity with sid as its ID
                break

        backing = cls(id=sid, data=data)
        backing.put()
        return backing

    @classmethod
    def delete_created_before(cls, cutoff):
        """Delete JSONSession entities created before cutoff.

        Args:
            cutoff: datetime.datetime object to the cutoff timestamp.
        """
        if not isinstance(cutoff, datetime.datetime):
            raise TypeError('cutoff must be a datetime.datetime.')
        keys = cls.query(cls.created < cutoff).fetch(keys_only=True)
        ndb.delete_multi(keys)

    @classmethod
    def delete_modified_before(cls, cutoff):
        """Delete JSONSession entities last modified before cutoff.

        Args:
            cutoff: datetime.datetime object to the cutoff timestamp.
        """
        if not isinstance(cutoff, datetime.datetime):
            raise TypeError('cutoff must be a datetime.datetime.')
        keys = cls.query(cls.modified < cutoff).fetch(keys_only=True)
        ndb.delete_multi(keys)

    @staticmethod
    def _get_new_sid():
        """Return a new string session ID without checking if it is being used.

        Returns:
            String session ID.
        """
        return security.generate_random_string(
            length=128, pool=security.ALPHANUMERIC)

    @staticmethod
    def _is_valid_sid(sid):
        """Return whether the session ID sid is alphanumeric and 128 chars.

        Args:
            sid: String session ID.
        Returns:
            True if sid is alphanumeric and 128 characters. False otherwise.
        """
        if isinstance(sid, basestring) and (len(sid) == 128):
            for c in sid:
                if c not in security.ALPHANUMERIC:
                    return False
            else:
                return True
        return False

class JSONSessionFactory(sessions.CustomBackendSessionFactory):

    """Session factory that stores session data in a JSONSession entity."""

    session_model = JSONSession
    """The JSONSession entity model class."""

    def _get_by_sid(self, sid):
        """Return a SessionDict object for the session ID sid.

        Args:
            sid: String session ID.
        Returns:
            SessionDict object for the session ID sid or
            a new SessionDict object.
        """
        if self.session_model._is_valid_sid(sid):
            backing = self.session_model.get_by_id(sid)
            if isinstance(backing, self.session_model):
                self.sid = sid
                return sessions.SessionDict(self, data=backing.data)

        # Otherwise, sid is not valid or not found in the datastore
        # For the latter, even if this is a session fixation attack with
        # an old ID, returning an empty new session is the correct action
        # because it does not expose any information
        self.sid = None
        return sessions.SessionDict(self, new=True)

    def _is_valid_sid(self, sid):
        raise DeprecationWarning(
            'Generating the ID here makes the session vulnerable to fixation!')

    def _get_new_sid(self):
        raise DeprecationWarning(
            'Generating the ID here makes the session vulnerable to fixation!')

    def save_session(self, response):
        """Save the session and write the session ID to a secure cookie.

        If the special key "_logout" is found in the session, then the cookie
        is deleted. This implementation has the least impact on webapp2.
        """
        if not isinstance(self.session, sessions.SessionDict):
            return

        if '_logout' in self.session:
            if self.session_model._is_valid_sid(self.sid):
                key = ndb.Key(self.session_model, self.sid)
                key.delete()
            response.delete_cookie(
                self.name, path=self.session_args.get('path'),
                domain=self.session_args.get('domain'))
            return

        if not self.session.modified:
            # Defer saving the session until the next time it is modified
            return

        session_data = dict(self.session)
        if ((not self.session.new) and
            self.session_model._is_valid_sid(self.sid)):
            # Update the existing entity
            key = ndb.Key(self.session_model, self.sid)
            backing = key.get()
            if isinstance(backing, self.session_model):
                backing.data = session_data
                backing.put()
                return

        # Otherwise, the session is new or not found in the datastore
        # Save to a new entity and update the session ID
        backing = self.session_model._create(session_data)
        self.sid = backing.key.string_id()
        self.session_store.save_secure_cookie(
            response, self.name, {'_sid': self.sid}, **self.session_args)
