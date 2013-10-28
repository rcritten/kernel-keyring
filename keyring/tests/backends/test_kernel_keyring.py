import os
import tempfile
import sys

from ..py30compat import unittest

from ..test_backend import BackendBasicTests
from ..util import random_string

from keyring.backends import kernel_keyring

class KernelKeyringTests(BackendBasicTests):

    def setUp(self):
        if not kernel_keyring.VolatileKernelKeyring.viable():
            self.skipTest("keyctl not available")
        super(KernelKeyringTests, self).setUp()
        self.keyring = self.init_keyring()

    def tearDown(self):
        self.keyring.kernel_keyring.clear_value(self.keyring.kernel_key)
        try:
            os.unlink(self.keyring.file_path)
        except (OSError,):
            e = sys.exc_info()[1]
            if e.errno != 2: # No such file or directory
                raise

    def test_encrypt_decrypt(self):
        password = random_string(20)
        # keyring.encrypt expects bytes
        password = password.encode('utf-8')
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))


class BadSyncKernelKeyringTests(object):

    def setUp(self):
        if not kernel_keyring.VolatileKernelKeyring.viable():
            self.skipTest("keyctl not available")
        super(BadSyncKernelKeyringTests, self).setUp()
        self.keyring = self.init_keyring()

    # This specifically tests without tearing down the keyring or
    # file between tests.

    def test_key_no_kernel_keyring(self):
        # Set a password in the keyring and delete the kernel key
        self.keyring.set_password('service1', 'username1', 'password1')
        self.keyring.kernel_keyring.clear_value(self.keyring.kernel_key)
        # On no-match a query returns None and a new key is set
        self.assertEqual(self.keyring.get_password('service1', 'username1'), None)

    def test_key_no_file(self):
        # Set a password in the keyring and delete the keyring file
        self.keyring.set_password('service1', 'username1', 'password1')
        try:
            os.unlink(self.keyring.file_path)
        except (OSError,):
            e = sys.exc_info()[1]
            if e.errno != 2: # No such file or directory
                raise
        # On no-match a query returns None and a new key is set
        self.assertEqual(self.keyring.get_password('service1', 'username1'), None)

        # Clean up after final test
        self.keyring.kernel_keyring.clear_value(self.keyring.kernel_key)


class EncryptedFileKeyringTestCase(KernelKeyringTests, unittest.TestCase):

    def init_keyring(self):
        keyring = kernel_keyring.VolatileKernelEncryptedKeyring()
        keyring.kernel_key = 'python-keyring-unit-tests'
        keyring.filename = 'python-keyring-unit-tests'
        return keyring


class BadSyncKeyringTestCase(BadSyncKernelKeyringTests, unittest.TestCase):

    def init_keyring(self):
        keyring = kernel_keyring.VolatileKernelEncryptedKeyring()
        keyring.kernel_key = 'python-keyring-unit-tests'
        keyring.filename = 'python-keyring-unit-tests'
        return keyring


class UserEncryptedFileKeyringTestCase(KernelKeyringTests, unittest.TestCase):
    """Test using a non-default keyring type"""

    def init_keyring(self):
        keyring = kernel_keyring.VolatileKernelEncryptedKeyring('@u')
        keyring.kernel_key = 'python-keyring-unit-tests'
        keyring.filename = 'python-keyring-unit-tests'
        return keyring


class UserBadSyncKeyringTestCase(BadSyncKernelKeyringTests, unittest.TestCase):
    """Test using a non-default keyring type"""

    def init_keyring(self):
        keyring = kernel_keyring.VolatileKernelEncryptedKeyring('@u')
        keyring.kernel_key = 'python-keyring-unit-tests'
        keyring.filename = 'python-keyring-unit-tests'
        return keyring
