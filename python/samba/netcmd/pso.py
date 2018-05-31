# Manages Password Settings Objects
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
import samba.getopt as options
import ldb
from samba.samdb import SamDB
from samba.netcmd import (Command, CommandError, Option, SuperCommand)
from samba.dcerpc.samr import (DOMAIN_PASSWORD_COMPLEX,
                               DOMAIN_PASSWORD_STORE_CLEARTEXT)
from samba.auth import system_session

NEVER_TIMESTAMP = int(-0x8000000000000000)


def pso_container(samdb):
    return "CN=Password Settings Container,CN=System,%s" % samdb.domain_dn()


def timestamp_to_mins(timestamp_str):
    """Converts a timestamp in -100 nanosecond units to minutes"""
    # treat a timestamp of 'never' the same as zero (this should work OK for
    # most settings, and it displays better than trying to convert
    # -0x8000000000000000 to minutes)
    if int(timestamp_str) == NEVER_TIMESTAMP:
        return 0
    else:
        return abs(int(timestamp_str)) / (1e7 * 60)


def timestamp_to_days(timestamp_str):
    """Converts a timestamp in -100 nanosecond units to days"""
    return timestamp_to_mins(timestamp_str) / (60 * 24)


def mins_to_timestamp(mins):
    """Converts a value in minutes to -100 nanosecond units"""
    timestamp = -int((1e7) * 60 * mins)
    return str(timestamp)


def days_to_timestamp(days):
    """Converts a value in days to -100 nanosecond units"""
    timestamp = mins_to_timestamp(days * 60 * 24)
    return str(timestamp)


def show_pso_by_dn(outf, samdb, dn, show_applies_to=True):
    """Displays the password settings for a PSO specified by DN"""

    # map from the boolean LDB value to the CLI string the user sees
    on_off_str = {"TRUE": "on", "FALSE": "off"}

    pso_attrs = ['name', 'msDS-PasswordSettingsPrecedence',
                 'msDS-PasswordReversibleEncryptionEnabled',
                 'msDS-PasswordHistoryLength', 'msDS-MinimumPasswordLength',
                 'msDS-PasswordComplexityEnabled', 'msDS-MinimumPasswordAge',
                 'msDS-MaximumPasswordAge', 'msDS-LockoutObservationWindow',
                 'msDS-LockoutThreshold', 'msDS-LockoutDuration',
                 'msDS-PSOAppliesTo']

    res = samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=pso_attrs)
    pso_res = res[0]
    outf.write("Password information for PSO '%s'\n" % pso_res['name'])
    outf.write("\n")

    outf.write("Precedence (lowest is best): %s\n" %
               pso_res['msDS-PasswordSettingsPrecedence'])
    bool_str = str(pso_res['msDS-PasswordComplexityEnabled'])
    outf.write("Password complexity: %s\n" % on_off_str[bool_str])
    bool_str = str(pso_res['msDS-PasswordReversibleEncryptionEnabled'])
    outf.write("Store plaintext passwords: %s\n" % on_off_str[bool_str])
    outf.write("Password history length: %s\n" %
               pso_res['msDS-PasswordHistoryLength'])
    outf.write("Minimum password length: %s\n" %
               pso_res['msDS-MinimumPasswordLength'])
    outf.write("Minimum password age (days): %d\n" %
               timestamp_to_days(pso_res['msDS-MinimumPasswordAge'][0]))
    outf.write("Maximum password age (days): %d\n" %
               timestamp_to_days(pso_res['msDS-MaximumPasswordAge'][0]))
    outf.write("Account lockout duration (mins): %d\n" %
               timestamp_to_mins(pso_res['msDS-LockoutDuration'][0]))
    outf.write("Account lockout threshold (attempts): %s\n" %
               pso_res['msDS-LockoutThreshold'])
    outf.write("Reset account lockout after (mins): %d\n" %
               timestamp_to_mins(pso_res['msDS-LockoutObservationWindow'][0]))

    if show_applies_to:
        if 'msDS-PSOAppliesTo' in pso_res:
            outf.write("\nPSO applies directly to %d groups/users:\n" %
                       len(pso_res['msDS-PSOAppliesTo']))
            for dn in pso_res['msDS-PSOAppliesTo']:
                outf.write("  %s\n" % dn)
        else:
            outf.write("\nNote: PSO does not apply to any users or groups.\n")


def check_pso_valid(samdb, pso_dn, name):
    """Gracefully bail out if we can't view/modify the PSO specified"""
    # the base scope search for the PSO throws an error if it doesn't exist
    try:
        res = samdb.search(pso_dn, scope=ldb.SCOPE_BASE,
                           attrs=['msDS-PasswordSettingsPrecedence'])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            raise CommandError("Unable to find PSO '%s'" % name)
        raise

    # users need admin permission to modify/view a PSO. In this case, the
    # search succeeds, but it doesn't return any attributes
    if 'msDS-PasswordSettingsPrecedence' not in res[0]:
        raise CommandError("You may not have permission to view/modify PSOs")


def show_pso_for_user(outf, samdb, username):
    """Displays the password settings for a specific user"""

    search_filter = "(&(sAMAccountName=%s)(objectClass=user))" % username

    res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                       expression=search_filter,
                       attrs=['msDS-ResultantPSO', 'msDS-PSOApplied'])

    if len(res) == 0:
        outf.write("User '%s' not found.\n" % username)
    elif 'msDS-ResultantPSO' not in res[0]:
        outf.write("No PSO applies to user '%s'. "
                   "The default domain settings apply.\n" % username)
        outf.write("Refer to 'samba-tool domain passwordsettings show'.\n")
    else:
        # sanity-check user has permissions to view PSO details (non-admin
        # users can view msDS-ResultantPSO, but not the actual PSO details)
        check_pso_valid(samdb, res[0]['msDS-ResultantPSO'][0], "???")
        outf.write("The following PSO settings apply to user '%s'.\n\n" %
                   username)
        show_pso_by_dn(outf, samdb, res[0]['msDS-ResultantPSO'][0],
                       show_applies_to=False)
        # PSOs that apply directly to a user don't necessarily have the best
        # precedence, which could be a little confusing for PSO management
        if 'msDS-PSOApplied' in res[0]:
            outf.write("\nNote: PSO applies directly to user "
                       "(any group PSOs are overridden)\n")
        else:
            outf.write("\nPSO applies to user via group membership.\n")


def msg_add_attr(msg, attr_name, value, ldb_oper):
    msg[attr_name] = ldb.MessageElement(value, ldb_oper, attr_name)


def make_pso_ldb_msg(outf, samdb, pso_dn, create, lockout_threshold=None,
                     complexity=None, precedence=None, store_plaintext=None,
                     history_length=None, min_pwd_length=None,
                     min_pwd_age=None, max_pwd_age=None, lockout_duration=None,
                     reset_lockout_after=None):
    """Packs the given PSO settings into an LDB message"""

    m = ldb.Message()
    m.dn = ldb.Dn(samdb, pso_dn)

    if create:
        ldb_oper = ldb.FLAG_MOD_ADD
        m["msDS-objectClass"] = ldb.MessageElement("msDS-PasswordSettings",
                                                   ldb_oper, "objectClass")
    else:
        ldb_oper = ldb.FLAG_MOD_REPLACE

    if precedence is not None:
        msg_add_attr(m, "msDS-PasswordSettingsPrecedence", str(precedence),
                     ldb_oper)

    if complexity is not None:
        bool_str = "TRUE" if complexity == "on" else "FALSE"
        msg_add_attr(m, "msDS-PasswordComplexityEnabled", bool_str, ldb_oper)

    if store_plaintext is not None:
        bool_str = "TRUE" if store_plaintext == "on" else "FALSE"
        msg_add_attr(m, "msDS-PasswordReversibleEncryptionEnabled",
                     bool_str, ldb_oper)

    if history_length is not None:
        msg_add_attr(m, "msDS-PasswordHistoryLength", str(history_length),
                     ldb_oper)

    if min_pwd_length is not None:
        msg_add_attr(m, "msDS-MinimumPasswordLength", str(min_pwd_length),
                     ldb_oper)

    if min_pwd_age is not None:
        min_pwd_age_ticks = days_to_timestamp(min_pwd_age)
        msg_add_attr(m, "msDS-MinimumPasswordAge", min_pwd_age_ticks,
                     ldb_oper)

    if max_pwd_age is not None:
        # Windows won't let you set max-pwd-age to zero. Here we take zero to
        # mean 'never expire' and use the timestamp corresponding to 'never'
        if max_pwd_age == 0:
            max_pwd_age_ticks = str(NEVER_TIMESTAMP)
        else:
            max_pwd_age_ticks = days_to_timestamp(max_pwd_age)
        msg_add_attr(m, "msDS-MaximumPasswordAge", max_pwd_age_ticks, ldb_oper)

    if lockout_duration is not None:
        lockout_duration_ticks = mins_to_timestamp(lockout_duration)
        msg_add_attr(m, "msDS-LockoutDuration", lockout_duration_ticks,
                     ldb_oper)

    if lockout_threshold is not None:
        msg_add_attr(m, "msDS-LockoutThreshold", str(lockout_threshold),
                     ldb_oper)

    if reset_lockout_after is not None:
        msg_add_attr(m, "msDS-LockoutObservationWindow",
                     mins_to_timestamp(reset_lockout_after), ldb_oper)

    return m


def check_pso_constraints(min_pwd_length=None, history_length=None,
                          min_pwd_age=None, max_pwd_age=None):
    """Checks PSO settings fall within valid ranges"""

    # check values as per section 3.1.1.5.2.2 Constraints in MS-ADTS spec
    if history_length is not None and history_length > 1024:
        raise CommandError("Bad password history length: "
                           "valid range is 0 to 1024")

    if min_pwd_length is not None and min_pwd_length > 255:
        raise CommandError("Bad minimum password length: "
                           "valid range is 0 to 255")

    if min_pwd_age is not None and max_pwd_age is not None:
        # note max-age=zero is a special case meaning 'never expire'
        if min_pwd_age >= max_pwd_age and max_pwd_age != 0:
            raise CommandError("Minimum password age must be less than "
                               "maximum age")


# the same args are used for both create and set commands
pwd_settings_options = [
    Option("--complexity", type="choice", choices=["on", "off"],
           help="The password complexity (on | off)."),
    Option("--store-plaintext", type="choice", choices=["on", "off"],
           help="Store plaintext passwords where account have "
           "'store passwords with reversible encryption' set (on | off)."),
    Option("--history-length",
           help="The password history length (<integer>).", type=int),
    Option("--min-pwd-length",
           help="The minimum password length (<integer>).", type=int),
    Option("--min-pwd-age",
           help=("The minimum password age (<integer in days>). "
                 "Default is domain setting."), type=int),
    Option("--max-pwd-age",
           help=("The maximum password age (<integer in days>). "
                 "Default is domain setting."), type=int),
    Option("--account-lockout-duration", type=int,
           help=("The length of time an account is locked out after exceeding "
                 "the limit on bad password attempts (<integer in mins>). "
                 "Default is domain setting")),
    Option("--account-lockout-threshold", type=int,
           help=("The number of bad password attempts allowed before locking "
                 "out the account (<integer>). Default is domain setting.")),
    Option("--reset-account-lockout-after",
           help=("After this time is elapsed, the recorded number of attempts "
                 "restarts from zero (<integer in mins>). "
                 "Default is domain setting."), type=int)]


def num_options_in_args(options, args):
    """
    Returns the number of options specified that are present in the args.
    (There can be other args besides just the ones we're interested in, which
    is why argc on its own is not enough)
    """
    num_opts = 0
    for opt in options:
        for arg in args:
            # The option should be a sub-string of the CLI argument for a match
            if str(opt) in arg:
                num_opts += 1
    return num_opts


class cmd_domain_pwdsettings_pso_create(Command):
    """Creates a new Password Settings Object (PSO).

    PSOs are a way to tailor different password settings (lockout policy,
    minimum password length, etc) for specific users or groups.

    The psoname is a unique name for the new Password Settings Object.
    When multiple PSOs apply to a user, the precedence determines which PSO
    will take effect. The PSO with the lowest precedence will take effect.

    For most arguments, the default value (if unspecified) is the current
    domain passwordsettings value. To see these values, enter the command
    'samba-tool domain passwordsettings show'.

    To apply the new PSO to user(s) or group(s), enter the command
    'samba-tool domain passwordsettings pso apply'.
    """

    synopsis = "%prog <psoname> <precedence> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = pwd_settings_options + [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]
    takes_args = ["psoname", "precedence"]

    def run(self, psoname, precedence, H=None, min_pwd_age=None,
            max_pwd_age=None, complexity=None, store_plaintext=None,
            history_length=None, min_pwd_length=None,
            account_lockout_duration=None, account_lockout_threshold=None,
            reset_account_lockout_after=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            precedence = int(precedence)
        except ValueError:
            raise CommandError("The PSO's precedence should be "
                               "a numerical value. Try --help")

        # sanity-check that the PSO doesn't already exist
        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        try:
            res = samdb.search(pso_dn, scope=ldb.SCOPE_BASE)
        except ldb.LdbError as e:
            if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                pass
            else:
                raise
        else:
            raise CommandError("PSO '%s' already exists" % psoname)

        # we expect the user to specify at least one password-policy setting,
        # otherwise there's no point in creating a PSO
        num_pwd_args = num_options_in_args(pwd_settings_options, self.raw_argv)
        if num_pwd_args == 0:
            raise CommandError("Please specify at least one password policy "
                               "setting. Try --help")

        # it's unlikely that the user will specify all 9 password policy
        # settings on the CLI - current domain password-settings as the default
        # values for unspecified arguments
        if num_pwd_args < len(pwd_settings_options):
            self.message("Not all password policy options "
                         "have been specified.")
            self.message("For unspecified options, the current domain password"
                         " settings will be used as the default values.")

        # lookup the current domain password-settings
        res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_BASE,
                           attrs=["pwdProperties", "pwdHistoryLength", "minPwdLength",
                                  "minPwdAge", "maxPwdAge", "lockoutDuration",
                                  "lockoutThreshold", "lockOutObservationWindow"])
        assert(len(res) == 1)

        # use the domain settings for any missing arguments
        pwd_props = int(res[0]["pwdProperties"][0])
        if complexity is None:
            prop_flag = DOMAIN_PASSWORD_COMPLEX
            complexity = "on" if pwd_props & prop_flag else "off"

        if store_plaintext is None:
            prop_flag = DOMAIN_PASSWORD_STORE_CLEARTEXT
            store_plaintext = "on" if pwd_props & prop_flag else "off"

        if history_length is None:
            history_length = int(res[0]["pwdHistoryLength"][0])

        if min_pwd_length is None:
            min_pwd_length = int(res[0]["minPwdLength"][0])

        if min_pwd_age is None:
            min_pwd_age = timestamp_to_days(res[0]["minPwdAge"][0])

        if max_pwd_age is None:
            max_pwd_age = timestamp_to_days(res[0]["maxPwdAge"][0])

        if account_lockout_duration is None:
            account_lockout_duration = \
                timestamp_to_mins(res[0]["lockoutDuration"][0])

        if account_lockout_threshold is None:
            account_lockout_threshold = int(res[0]["lockoutThreshold"][0])

        if reset_account_lockout_after is None:
            reset_account_lockout_after = \
                timestamp_to_mins(res[0]["lockOutObservationWindow"][0])

        check_pso_constraints(max_pwd_age=max_pwd_age, min_pwd_age=min_pwd_age,
                              history_length=history_length,
                              min_pwd_length=min_pwd_length)

        # pack the settings into an LDB message
        m = make_pso_ldb_msg(self.outf, samdb, pso_dn, create=True,
                             complexity=complexity, precedence=precedence,
                             store_plaintext=store_plaintext,
                             history_length=history_length,
                             min_pwd_length=min_pwd_length,
                             min_pwd_age=min_pwd_age, max_pwd_age=max_pwd_age,
                             lockout_duration=account_lockout_duration,
                             lockout_threshold=account_lockout_threshold,
                             reset_lockout_after=reset_account_lockout_after)

        # create the new PSO
        try:
            samdb.add(m)
            self.message("PSO successfully created: %s" % pso_dn)
            # display the new PSO's settings
            show_pso_by_dn(self.outf, samdb, pso_dn, show_applies_to=False)
        except ldb.LdbError as e:
            (num, msg) = e.args
            if num == ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS:
                raise CommandError("Administrator permissions are needed "
                                   "to create a PSO.")
            else:
                raise CommandError("Failed to create PSO '%s': %s" % (pso_dn,
                                                                      msg))


class cmd_domain_pwdsettings_pso_set(Command):
    """Modifies a Password Settings Object (PSO)."""

    synopsis = "%prog <psoname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = pwd_settings_options + [
        Option("--precedence", type=int,
               help=("This PSO's precedence relative to other PSOs. "
                     "Lower precedence is better (<integer>).")),
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]
    takes_args = ["psoname"]

    def run(self, psoname, H=None, precedence=None, min_pwd_age=None,
            max_pwd_age=None, complexity=None, store_plaintext=None,
            history_length=None, min_pwd_length=None,
            account_lockout_duration=None, account_lockout_threshold=None,
            reset_account_lockout_after=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        # sanity-check the PSO exists
        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        check_pso_valid(samdb, pso_dn, psoname)

        # we expect the user to specify at least one password-policy setting
        num_pwd_args = num_options_in_args(pwd_settings_options, self.raw_argv)
        if num_pwd_args == 0 and precedence is None:
            raise CommandError("Please specify at least one password policy "
                               "setting. Try --help")

        if min_pwd_age is not None or max_pwd_age is not None:
            # if we're modifying either the max or min pwd-age, check the max
            # is always larger. We may have to fetch the PSO's setting to
            # verify this
            res = samdb.search(pso_dn, scope=ldb.SCOPE_BASE,
                               attrs=['msDS-MinimumPasswordAge',
                                      'msDS-MaximumPasswordAge'])
            if min_pwd_age is None:
                min_pwd_ticks = res[0]['msDS-MinimumPasswordAge'][0]
                min_pwd_age = timestamp_to_days(min_pwd_ticks)

            if max_pwd_age is None:
                max_pwd_ticks = res[0]['msDS-MaximumPasswordAge'][0]
                max_pwd_age = timestamp_to_days(max_pwd_ticks)

        check_pso_constraints(max_pwd_age=max_pwd_age, min_pwd_age=min_pwd_age,
                              history_length=history_length,
                              min_pwd_length=min_pwd_length)

        # pack the settings into an LDB message
        m = make_pso_ldb_msg(self.outf, samdb, pso_dn, create=False,
                             complexity=complexity, precedence=precedence,
                             store_plaintext=store_plaintext,
                             history_length=history_length,
                             min_pwd_length=min_pwd_length,
                             min_pwd_age=min_pwd_age, max_pwd_age=max_pwd_age,
                             lockout_duration=account_lockout_duration,
                             lockout_threshold=account_lockout_threshold,
                             reset_lockout_after=reset_account_lockout_after)

        # update the PSO
        try:
            samdb.modify(m)
            self.message("Successfully updated PSO: %s" % pso_dn)
            # display the new PSO's settings
            show_pso_by_dn(self.outf, samdb, pso_dn, show_applies_to=False)
        except ldb.LdbError as e:
            (num, msg) = e.args
            raise CommandError("Failed to update PSO '%s': %s" % (pso_dn, msg))


class cmd_domain_pwdsettings_pso_delete(Command):
    """Deletes a Password Settings Object (PSO)."""

    synopsis = "%prog <psoname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]
    takes_args = ["psoname"]

    def run(self, psoname, H=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        # sanity-check the PSO exists
        check_pso_valid(samdb, pso_dn, psoname)

        samdb.delete(pso_dn)
        self.message("Deleted PSO %s" % psoname)


def pso_key(a):
    a_precedence = int(a['msDS-PasswordSettingsPrecedence'][0])
    return a_precedence


class cmd_domain_pwdsettings_pso_list(Command):
    """Lists all Password Settings Objects (PSOs)."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        res = samdb.search(pso_container(samdb), scope=ldb.SCOPE_SUBTREE,
                           attrs=['name', 'msDS-PasswordSettingsPrecedence'],
                           expression="(objectClass=msDS-PasswordSettings)")

        # an unprivileged search against Windows returns nothing here. On Samba
        # we get the PSO names, but not their attributes
        if len(res) == 0 or 'msDS-PasswordSettingsPrecedence' not in res[0]:
            self.outf.write("No PSOs are present, or you don't have permission"
                            " to view them.\n")
            return

        # sort the PSOs so they're displayed in order of precedence
        pso_list = sorted(res, key=pso_key)

        self.outf.write("Precedence | PSO name\n")
        self.outf.write("--------------------------------------------------\n")

        for pso in pso_list:
            precedence = pso['msDS-PasswordSettingsPrecedence']
            self.outf.write("%-10s | %s\n" % (precedence, pso['name']))


class cmd_domain_pwdsettings_pso_show(Command):
    """Display a Password Settings Object's details."""

    synopsis = "%prog <psoname> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]
    takes_args = ["psoname"]

    def run(self, psoname, H=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        check_pso_valid(samdb, pso_dn, psoname)
        show_pso_by_dn(self.outf, samdb, pso_dn)


class cmd_domain_pwdsettings_pso_show_user(Command):
    """Displays the Password Settings that apply to a user."""

    synopsis = "%prog <username> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]
    takes_args = ["username"]

    def run(self, username, H=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        show_pso_for_user(self.outf, samdb, username)


class cmd_domain_pwdsettings_pso_apply(Command):
    """Applies a PSO's password policy to a user or group.

    When a PSO is applied to a group, it will apply to all users (and groups)
    that are members of that group. If a PSO applies directly to a user, it
    will override any group membership PSOs for that user.

    When multiple PSOs apply to a user, either directly or through group
    membership, the PSO with the lowest precedence will take effect.
    """

    synopsis = "%prog <psoname> <user-or-group-name> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str)
    ]
    takes_args = ["psoname", "user_or_group"]

    def run(self, psoname, user_or_group, H=None, credopts=None,
            sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        # sanity-check the PSO exists
        check_pso_valid(samdb, pso_dn, psoname)

        # lookup the user/group by account-name to gets its DN
        search_filter = "(sAMAccountName=%s)" % user_or_group
        res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                           expression=search_filter)

        if len(res) == 0:
            raise CommandError("The specified user or group '%s' was not found"
                               % user_or_group)

        # modify the PSO to apply to the user/group specified
        target_dn = str(res[0].dn)
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, pso_dn)
        m["msDS-PSOAppliesTo"] = ldb.MessageElement(target_dn,
                                                    ldb.FLAG_MOD_ADD,
                                                    "msDS-PSOAppliesTo")
        try:
            samdb.modify(m)
        except ldb.LdbError as e:
            (num, msg) = e.args
            # most likely error - PSO already applies to that user/group
            if num == ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS:
                raise CommandError("PSO '%s' already applies to '%s'"
                                   % (psoname, user_or_group))
            else:
                raise CommandError("Failed to update PSO '%s': %s" % (psoname,
                                                                      msg))

        self.message("PSO '%s' applied to '%s'" % (psoname, user_or_group))


class cmd_domain_pwdsettings_pso_unapply(Command):
    """Updates a PSO to no longer apply to a user or group."""

    synopsis = "%prog <psoname> <user-or-group-name> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               metavar="URL", dest="H", type=str),
    ]
    takes_args = ["psoname", "user_or_group"]

    def run(self, psoname, user_or_group, H=None, credopts=None,
            sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        pso_dn = "CN=%s,%s" % (psoname, pso_container(samdb))
        # sanity-check the PSO exists
        check_pso_valid(samdb, pso_dn, psoname)

        # lookup the user/group by account-name to gets its DN
        search_filter = "(sAMAccountName=%s)" % user_or_group
        res = samdb.search(samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                           expression=search_filter)

        if len(res) == 0:
            raise CommandError("The specified user or group '%s' was not found"
                               % user_or_group)

        # modify the PSO to apply to the user/group specified
        target_dn = str(res[0].dn)
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, pso_dn)
        m["msDS-PSOAppliesTo"] = ldb.MessageElement(target_dn,
                                                    ldb.FLAG_MOD_DELETE,
                                                    "msDS-PSOAppliesTo")
        try:
            samdb.modify(m)
        except ldb.LdbError as e:
            (num, msg) = e.args
            # most likely error - PSO doesn't apply to that user/group
            if num == ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise CommandError("PSO '%s' doesn't apply to '%s'"
                                   % (psoname, user_or_group))
            else:
                raise CommandError("Failed to update PSO '%s': %s" % (psoname,
                                                                      msg))
        self.message("PSO '%s' no longer applies to '%s'" % (psoname,
                                                             user_or_group))


class cmd_domain_passwordsettings_pso(SuperCommand):
    """Manage fine-grained Password Settings Objects (PSOs)."""

    subcommands = {}
    subcommands["apply"] = cmd_domain_pwdsettings_pso_apply()
    subcommands["create"] = cmd_domain_pwdsettings_pso_create()
    subcommands["delete"] = cmd_domain_pwdsettings_pso_delete()
    subcommands["list"] = cmd_domain_pwdsettings_pso_list()
    subcommands["set"] = cmd_domain_pwdsettings_pso_set()
    subcommands["show"] = cmd_domain_pwdsettings_pso_show()
    subcommands["show-user"] = cmd_domain_pwdsettings_pso_show_user()
    subcommands["unapply"] = cmd_domain_pwdsettings_pso_unapply()
