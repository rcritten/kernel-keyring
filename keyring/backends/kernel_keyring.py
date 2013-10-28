import os
import keyring
import random
import subprocess
from keyring.util import properties
from keyring.backend import KeyringBackend

KEYTYPE = 'user'
KEYRING_TOKEN = 'python-keyring'

"""
IMPORTANT: This backend differs from other keyring backends in that
           it is not persistent and not necessarily shared between the same
           user in different shells (see keyring_type). Any data stored
           in this backend will not be preserved between reboots at a
           minimum, and could be cleared at other times as well. Calling
           programs need to be able to handle refreshing credentials stored
           in this backend.

PURPOSE: Why have this backend at all? It is so you can provide arbitrarily
         large password storage in a secure way without user-intervention.
         This combines a file-based backend with the Linux kernel to store
         the key to that backend. The kernel has limited memory available
         to store data in its own keyring, using a file provides
         significantly more space.
"""

def _run(args, stdin=None):
    """
    Function to execute an external program.

    Returns a tuple of stdout, stderr, returncode.
    """
    process = subprocess.Popen(args,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    output, err = process.communicate(stdin)
    retcode = process.poll()
    return (output, err, retcode)


class VolatileKernelKeyring(KeyringBackend):
    """
    This backend is intended to be used with another backend to provide
    the actual password storage. This backend manages only the key to
    the other backend so that no user-intervention is required.
    """

    def __init__(self, keyring_type):
        """
        keyring_type can be one of:
          Thread keyring: @t
          Process keyring: @p
          Session keyring: @s
          User keyring: @u
          User default session keyring: @us
          Group-specific keyring: @g

          See man keyctl for more information.
        """
        if str(keyring_type) not in ['@t', '@p', '@s', '@u', '@us', '@g']:
            raise RuntimeError("keyring type '%s' not supported." %
                keyring_type)
        self._keyring_type = keyring_type

    @properties.ClassProperty
    @classmethod
    def priority(self):
        return 0

    @classmethod
    def viable(cls):
        try:
            stdout, stderr, retcode = _run(['keyctl', 'show'])
        except Exception:
            return False
        return True

    def get_password(self, service, username):
        """Get password of the username for the service
        """
        raise NotImplementedError('handled at a higher level')

    def set_password(self, service, username, password):
        """Set password for the username of the service
        """
        raise NotImplementedError('handled at a higher level')

    def delete_password(self, service, username):
        """Delete the password for the username of the service.
        """
        raise NotImplementedError('handled at a higher level')

    def _get_real_key(self, key):
        """
        One cannot request a key based on the description it was created with
        so find the one we're looking for.
        """
        (stdout, stderr, retcode) = _run(['keyctl',
                                          'search',
                                          self._keyring_type,
                                          KEYTYPE,
                                          key])
        if retcode:
            raise ValueError('key %s not found' % key)

        return stdout.rstrip()

    def _has_key(self, key):
        """
        Returns True/False whether the key exists in the keyring.
        """
        try:
            self._get_real_key(key)
            return True
        except ValueError:
            return False

    def set_value(self, key, value):
        """
        Store the value into the kernel keyring.
        """
        if self._has_key(key):
            real_key = self._get_real_key(key)
            (stdout, stderr, retcode) = _run(['keyctl',
                                              'pupdate',
                                              real_key],
                                              stdin=value)
        else:
            (stdout, stderr, retcode) = _run(['keyctl',
                                              'padd',
                                              KEYTYPE,
                                              key,
                                              self._keyring_type],
                                              stdin=value)
        if retcode:
            raise ValueError('Storing key failed: %s' % stderr)

    def get_value(self, key):
        """
        Retrieve a key from the keyring.
        """
        try:
            real_key = self._get_real_key(key)
        except ValueError:
            return None

        (stdout, stderr, retcode) = _run(['keyctl',
                                          'pipe',
                                          real_key])
        if retcode:
            raise ValueError('Retrieve key failed: %s' % stderr)

        return stdout

    def clear_value(self, key):
        """
        Remove a key from the kernel keyring.
        """
        try:
            real_key = self._get_real_key(key)
        except ValueError:
            return

        (stdout, stderr, retcode) = _run(['keyctl',
                                          'unlink',
                                          real_key,
                                          self._keyring_type])
        if retcode:
            raise ValueError('Clear entry failed: %s' % stderr)


class VolatileKernelEncryptedKeyring(keyring.backends.file.EncryptedKeyring):
    """
    Provide an interface to an encrypted python-keyring data store without
    requiring user-intervention by storing the password in the kernel
    keyring.

    The data stored in this keyring is considered ephemeral and easily
    replaced. If either one is missing then dump all contents and start
    over.
    """

    filename = 'kernel_encrypted_keyring.cfg'
    kernel_key = KEYRING_TOKEN

    def __init__(self, keyring_type='@s'):
        self.kernel_keyring = VolatileKernelKeyring(keyring_type)

    @properties.NonDataProperty
    def file_path(self):
        """
        Store the keyring in the runtime dir. This password cache is cheap
        and there is no need or desire for it to persist across reboots.
        """
        if 'XDG_RUNTIME_DIR' in os.environ:
            runtime_dir = os.environ['XDG_RUNTIME_DIR']
            return os.path.join(runtime_dir, self.filename)
        else:
            return os.path.join(keyring.util.platform.data_root(), self.filename)

    def _get_new_password(self):
        """
        Fetch or initialize a new keyring password.
        """
        n_bits = 128
        key = self.kernel_keyring.get_value(self.kernel_key)
        if key is None:
            key = '%0*x' % (n_bits >> 2, random.getrandbits(n_bits))

            self.kernel_keyring.set_value(self.kernel_key, key)

        return key

    def get_password(self, service, username):
        """
        See if the current kernel keyring password can decrypt the
        encrypted file. If not then drop the file, we're starting over.
        """
        key = self.keyring_key = self.kernel_keyring.get_value(self.kernel_key)
        if key is None:
            self._lock()
            return None

        try:
            ref_pw = super(VolatileKernelEncryptedKeyring, self).get_password('keyring-setting', 'password reference')
            assert ref_pw == 'password reference value'
        except AssertionError:
            self._lock()
            return None
        else:
            return super(VolatileKernelEncryptedKeyring, self).get_password(service, username)

    def _unlock(self):
        """
        Unlock the keyring.
        """
        # _get_new_password() is a bit of a mis-nomer. It will return
        # the current kernel keyring password if one is set.
        self.keyring_key = self._get_new_password()

    def _lock(self):
        """
        Drop the keyring.
        """
        if os.path.exists(self.file_path):
            os.unlink(self.file_path)
        self.kernel_keyring.clear_value(self.kernel_key)
        super(VolatileKernelEncryptedKeyring, self)._lock()
