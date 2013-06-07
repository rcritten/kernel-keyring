import os
import keyring
import random
import subprocess
from keyring.util import properties

KEYRING = '@s'
KEYTYPE = 'user'
KEYRING_TOKEN = 'python-keyring'


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


class KernelKeyring(object):

    @classmethod
    def viable(cls):
        try:
            stdout, stderr, retcode = _run(['keyctl', 'show'])
        except Exception:
            return False
        return True

    def _get_real_key(self, key):
        """
        One cannot request a key based on the description it was created with
        so find the one we're looking for.
        """
        (stdout, stderr, retcode) = _run(['keyctl',
                                          'search',
                                          KEYRING,
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
                                              KEYRING],
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
                                          KEYRING])
        if retcode:
            raise ValueError('Clear entry failed: %s' % stderr)


class KernelEncryptedKeyring(keyring.backends.file.EncryptedKeyring):
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
    kernel_keyring = KernelKeyring()

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
            ref_pw = super(KernelEncryptedKeyring, self).get_password('keyring-setting', 'password reference')
            assert ref_pw == 'password reference value'
        except AssertionError:
            self._lock()
            return None
        else:
            return super(KernelEncryptedKeyring, self).get_password(service, username)

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
        super(KernelEncryptedKeyring, self)._lock()
