"""Base TestCase for tests that require the App Engine testbed."""

import unittest

from google.appengine.ext import ndb
from google.appengine.ext import testbed

class BaseTestCase(unittest.TestCase):

    """Base TestCase for tests that require the App Engine testbed.

    This class takes care of activating and deactivating the testbed and
    associated stubs.
    """

    def setUp(self):
        """Activate the testbed."""
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        # The testbed defaults to "_" as the application ID which sometimes
        # causes problems if a different application ID is in the environment
        self.testbed.setup_env(app_id='_', overwrite=True)

        # ndb uses both the datastore and the memcache
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        # Clear ndb's in-context cache between tests to prevent data leaks
        ndb.get_context().clear_cache()

        # URL fetch
        self.testbed.init_urlfetch_stub()

    def tearDown(self):
        """Deactivate the testbed."""
        self.testbed.deactivate()
