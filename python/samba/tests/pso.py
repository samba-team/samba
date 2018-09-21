#
# Helper classes for testing Password Settings Objects.
#
# This also tests the default password complexity (i.e. pwdProperties),
# minPwdLength, pwdHistoryLength settings as a side-effect.
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import ldb
from ldb import FLAG_MOD_DELETE, FLAG_MOD_ADD, FLAG_MOD_REPLACE
from samba.dcerpc.samr import (DOMAIN_PASSWORD_COMPLEX,
                               DOMAIN_PASSWORD_STORE_CLEARTEXT)


class TestUser:
    def __init__(self, username, samdb, userou=None):
        initial_password = "Initial12#"
        self.name = username
        self.ldb = samdb
        self.dn = "CN=%s,%s,%s" % (username, (userou or "CN=Users"),
                                   self.ldb.domain_dn())

        # store all passwords that have ever been used for this user, as well
        # as a pwd_history that more closely resembles the history on the DC
        self.all_old_passwords = [initial_password]
        self.pwd_history = [initial_password]
        self.ldb.newuser(username, initial_password, userou=userou)
        self.ldb.enable_account("(sAMAccountName=%s)" % username)
        self.last_pso = None

    def old_invalid_passwords(self, hist_len):
        """Returns the expected password history for the DC"""
        if hist_len == 0:
            return []

        # return the last n items in the list
        return self.pwd_history[-hist_len:]

    def old_valid_passwords(self, hist_len):
        """Returns old passwords that fall outside the DC's expected history"""
        # if PasswordHistoryLength is zero, any previous password can be valid
        if hist_len == 0:
            return self.all_old_passwords[:]

        # just exclude our pwd_history if there's not much in it. This can
        # happen if we've been using a lower PasswordHistoryLength setting
        # previously
        hist_len = min(len(self.pwd_history), hist_len)

        # return any passwords up to the nth-from-last item
        return self.all_old_passwords[:-hist_len]

    def update_pwd_history(self, new_password):
        """Updates the user's password history to reflect a password change"""
        # we maintain 2 lists: all passwords the user has ever had, and an
        # effective password-history that should roughly mirror the DC.
        # pwd_history_change() handles the corner-case where we need to
        # truncate password-history due to PasswordHistoryLength settings
        # changes
        if new_password in self.all_old_passwords:
            self.all_old_passwords.remove(new_password)
        self.all_old_passwords.append(new_password)

        if new_password in self.pwd_history:
            self.pwd_history.remove(new_password)
        self.pwd_history.append(new_password)

    def get_resultant_PSO(self):
        """Returns the DN of the applicable PSO, or None if none applies"""
        res = self.ldb.search(self.dn, attrs=['msDS-ResultantPSO'])

        if 'msDS-ResultantPSO' in res[0]:
            return str(res[0]['msDS-ResultantPSO'][0])
        else:
            return None

    def get_password(self):
        """Returns the user's current password"""
        # current password in the last item in the list
        return self.all_old_passwords[-1]

    def set_password(self, new_password):
        """Attempts to change a user's password"""
        ldif = """
dn: %s
changetype: modify
delete: userPassword
userPassword: %s
add: userPassword
userPassword: %s
""" % (self.dn, self.get_password(), new_password)
        # this modify will throw an exception if new_password doesn't meet the
        # PSO constraints (which the test code catches if it's expected to
        # fail)
        self.ldb.modify_ldif(ldif)
        self.update_pwd_history(new_password)

    def pwd_history_change(self, old_hist_len, new_hist_len):
        """
        Updates the effective password history, to reflect changes on the DC.
        When the PasswordHistoryLength applied to a user changes from a low
        setting (e.g. 2) to a higher setting (e.g. 4), passwords #3 and #4
        won't actually have been stored on the DC, so we need to make sure they
        are removed them from our mirror pwd_history list.
        """

        # our list may have been tracking more passwords than the DC actually
        # stores. Truncate the list now to match what the DC currently has
        hist_len = min(new_hist_len, old_hist_len)
        if hist_len == 0:
            self.pwd_history = []
        elif hist_len < len(self.pwd_history):
            self.pwd_history = self.pwd_history[-hist_len:]

        # corner-case where history-length goes from zero to non-zero. Windows
        # counts the current password as being in the history even before it
        # changes (Samba only counts it from the next change onwards). We don't
        # exercise this in the PSO tests due to this discrepancy, but the
        # following check will support the Windows behaviour
        if old_hist_len == 0 and new_hist_len > 0:
            self.pwd_history = [self.get_password()]

    def set_primary_group(self, group_dn):
        """Sets a user's primaryGroupID to be that of the specified group"""

        # get the primaryGroupToken of the group
        res = self.ldb.search(base=group_dn, attrs=["primaryGroupToken"],
                              scope=ldb.SCOPE_BASE)
        group_id = res[0]["primaryGroupToken"]

        # set primaryGroupID attribute of the user to that group
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, self.dn)
        m["primaryGroupID"] = ldb.MessageElement(group_id, FLAG_MOD_REPLACE,
                                                 "primaryGroupID")
        self.ldb.modify(m)


class PasswordSettings:
    def default_settings(self, samdb):
        """
        Returns a object representing the default password settings that will
        take effect (i.e. when no other Fine-Grained Password Policy applies)
        """
        pw_attrs = ["minPwdAge", "lockoutDuration", "lockOutObservationWindow",
                    "lockoutThreshold", "maxPwdAge", "minPwdAge",
                    "minPwdLength", "pwdHistoryLength", "pwdProperties"]
        res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_BASE,
                           attrs=pw_attrs)

        self.name = "Defaults"
        self.dn = None
        self.ldb = samdb
        self.precedence = 0
        self.complexity = \
            int(res[0]["pwdProperties"][0]) & DOMAIN_PASSWORD_COMPLEX
        self.store_plaintext = \
            int(res[0]["pwdProperties"][0]) & DOMAIN_PASSWORD_STORE_CLEARTEXT
        self.password_len = int(res[0]["minPwdLength"][0])
        self.lockout_attempts = int(res[0]["lockoutThreshold"][0])
        self.history_len = int(res[0]["pwdHistoryLength"][0])
        # convert to time in secs
        self.lockout_duration = int(res[0]["lockoutDuration"][0]) / -int(1e7)
        self.lockout_window =\
            int(res[0]["lockOutObservationWindow"][0]) / -int(1e7)
        self.password_age_min = int(res[0]["minPwdAge"][0]) / -int(1e7)
        self.password_age_max = int(res[0]["maxPwdAge"][0]) / -int(1e7)

    def __init__(self, name, samdb, precedence=10, complexity=True,
                 password_len=10, lockout_attempts=0, lockout_duration=5,
                 password_age_min=0, password_age_max=60 * 60 * 24 * 30,
                 history_len=2, store_plaintext=False, container=None):

        # if no PSO was specified, return an object representing the global
        # password settings (i.e. the default settings, if no PSO trumps them)
        if name is None:
            return self.default_settings(samdb)

        # only PSOs in the Password Settings Container are considered. You can
        # create PSOs outside of this container, but it's not recommended
        if container is None:
            base_dn = samdb.domain_dn()
            container = "CN=Password Settings Container,CN=System,%s" % base_dn

        self.name = name
        self.dn = "CN=%s,%s" % (name, container)
        self.ldb = samdb
        self.precedence = precedence
        self.complexity = complexity
        self.store_plaintext = store_plaintext
        self.password_len = password_len
        self.lockout_attempts = lockout_attempts
        self.history_len = history_len
        # times in secs
        self.lockout_duration = lockout_duration
        # lockout observation-window must be <= lockout-duration (the existing
        # lockout tests just use the same value for both settings)
        self.lockout_window = lockout_duration
        self.password_age_min = password_age_min
        self.password_age_max = password_age_max

        # add the PSO to the DB
        self.ldb.add_ldif(self.get_ldif())

    def get_ldif(self):
        complexity_str = "TRUE" if self.complexity else "FALSE"
        plaintext_str = "TRUE" if self.store_plaintext else "FALSE"

        # timestamps here are in units of -100 nano-seconds
        lockout_duration = -int(self.lockout_duration * (1e7))
        lockout_window = -int(self.lockout_window * (1e7))
        min_age = -int(self.password_age_min * (1e7))
        max_age = -int(self.password_age_max * (1e7))

        # all the following fields are mandatory for the PSO object
        ldif = """
dn: {0}
objectClass: msDS-PasswordSettings
msDS-PasswordSettingsPrecedence: {1}
msDS-PasswordReversibleEncryptionEnabled: {2}
msDS-PasswordHistoryLength: {3}
msDS-PasswordComplexityEnabled: {4}
msDS-MinimumPasswordLength: {5}
msDS-MinimumPasswordAge: {6}
msDS-MaximumPasswordAge: {7}
msDS-LockoutThreshold: {8}
msDS-LockoutObservationWindow: {9}
msDS-LockoutDuration: {10}
""".format(self.dn, self.precedence, plaintext_str, self.history_len,
           complexity_str, self.password_len, min_age, max_age,
           self.lockout_attempts, lockout_window, lockout_duration)

        return ldif

    def apply_to(self, user_group, operation=FLAG_MOD_ADD):
        """Updates this Password Settings Object to apply to a user or group"""
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, self.dn)
        m["msDS-PSOAppliesTo"] = ldb.MessageElement(user_group, operation,
                                                    "msDS-PSOAppliesTo")
        self.ldb.modify(m)

    def unapply(self, user_group):
        """Updates this PSO to no longer apply to a user or group"""
        # just delete the msDS-PSOAppliesTo attribute (instead of adding it)
        self.apply_to(user_group, operation=FLAG_MOD_DELETE)

    def set_precedence(self, new_precedence, samdb=None):
        if samdb is None:
            samdb = self.ldb
        ldif = """
dn: %s
changetype: modify
replace: msDS-PasswordSettingsPrecedence
msDS-PasswordSettingsPrecedence: %u
""" % (self.dn, new_precedence)
        samdb.modify_ldif(ldif)
        self.precedence = new_precedence
