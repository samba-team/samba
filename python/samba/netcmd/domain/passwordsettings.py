# domain management - domain passwordsettings
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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
import samba.getopt as options
from samba.auth import system_session
from samba.dcerpc.samr import (DOMAIN_PASSWORD_COMPLEX,
                               DOMAIN_PASSWORD_STORE_CLEARTEXT)
from samba.netcmd import Command, CommandError, Option, SuperCommand
from samba.netcmd.common import (NEVER_TIMESTAMP, timestamp_to_days,
                                 timestamp_to_mins)
from samba.netcmd.pso import cmd_domain_passwordsettings_pso
from samba.samdb import SamDB


class cmd_domain_passwordsettings_show(Command):
    """Display current password settings for the domain."""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
          ]

    def run(self, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_BASE,
                           attrs=["pwdProperties", "pwdHistoryLength", "minPwdLength",
                                  "minPwdAge", "maxPwdAge", "lockoutDuration", "lockoutThreshold",
                                  "lockOutObservationWindow"])
        assert(len(res) == 1)
        try:
            pwd_props = int(res[0]["pwdProperties"][0])
            pwd_hist_len = int(res[0]["pwdHistoryLength"][0])
            cur_min_pwd_len = int(res[0]["minPwdLength"][0])
            # ticks -> days
            cur_min_pwd_age = timestamp_to_days(res[0]["minPwdAge"][0])
            cur_max_pwd_age = timestamp_to_days(res[0]["maxPwdAge"][0])

            cur_account_lockout_threshold = int(res[0]["lockoutThreshold"][0])

            # ticks -> mins
            cur_account_lockout_duration = timestamp_to_mins(res[0]["lockoutDuration"][0])
            cur_reset_account_lockout_after = timestamp_to_mins(res[0]["lockOutObservationWindow"][0])
        except Exception as e:
            raise CommandError("Could not retrieve password properties!", e)

        self.message("Password information for domain '%s'" % domain_dn)
        self.message("")
        if pwd_props & DOMAIN_PASSWORD_COMPLEX != 0:
            self.message("Password complexity: on")
        else:
            self.message("Password complexity: off")
        if pwd_props & DOMAIN_PASSWORD_STORE_CLEARTEXT != 0:
            self.message("Store plaintext passwords: on")
        else:
            self.message("Store plaintext passwords: off")
        self.message("Password history length: %d" % pwd_hist_len)
        self.message("Minimum password length: %d" % cur_min_pwd_len)
        self.message("Minimum password age (days): %d" % cur_min_pwd_age)
        self.message("Maximum password age (days): %d" % cur_max_pwd_age)
        self.message("Account lockout duration (mins): %d" % cur_account_lockout_duration)
        self.message("Account lockout threshold (attempts): %d" % cur_account_lockout_threshold)
        self.message("Reset account lockout after (mins): %d" % cur_reset_account_lockout_after)


class cmd_domain_passwordsettings_set(Command):
    """Set password settings.

    Password complexity, password lockout policy, history length,
    minimum password length, the minimum and maximum password age) on
    a Samba AD DC server.

    Use against a Windows DC is possible, but group policy will override it.
    """

    synopsis = "%prog <options> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("--complexity", type="choice", choices=["on", "off", "default"],
               help="The password complexity (on | off | default). Default is 'on'"),
        Option("--store-plaintext", type="choice", choices=["on", "off", "default"],
               help="Store plaintext passwords where account have 'store passwords with reversible encryption' set (on | off | default). Default is 'off'"),
        Option("--history-length",
               help="The password history length (<integer> | default).  Default is 24.", type=str),
        Option("--min-pwd-length",
               help="The minimum password length (<integer> | default).  Default is 7.", type=str),
        Option("--min-pwd-age",
               help="The minimum password age (<integer in days> | default).  Default is 1.", type=str),
        Option("--max-pwd-age",
               help="The maximum password age (<integer in days> | default).  Default is 43.", type=str),
        Option("--account-lockout-duration",
               help="The length of time an account is locked out after exceeding the limit on bad password attempts (<integer in mins> | default).  Default is 30 mins.", type=str),
        Option("--account-lockout-threshold",
               help="The number of bad password attempts allowed before locking out the account (<integer> | default).  Default is 0 (never lock out).", type=str),
        Option("--reset-account-lockout-after",
               help="After this time is elapsed, the recorded number of attempts restarts from zero (<integer> | default).  Default is 30.", type=str),
    ]

    def run(self, H=None, min_pwd_age=None, max_pwd_age=None,
            quiet=False, complexity=None, store_plaintext=None, history_length=None,
            min_pwd_length=None, account_lockout_duration=None, account_lockout_threshold=None,
            reset_account_lockout_after=None, credopts=None, sambaopts=None,
            versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        msgs = []
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, domain_dn)
        pwd_props = int(samdb.get_pwdProperties())

        # get the current password age settings
        max_pwd_age_ticks = samdb.get_maxPwdAge()
        min_pwd_age_ticks = samdb.get_minPwdAge()

        if complexity is not None:
            if complexity == "on" or complexity == "default":
                pwd_props = pwd_props | DOMAIN_PASSWORD_COMPLEX
                msgs.append("Password complexity activated!")
            elif complexity == "off":
                pwd_props = pwd_props & (~DOMAIN_PASSWORD_COMPLEX)
                msgs.append("Password complexity deactivated!")

        if store_plaintext is not None:
            if store_plaintext == "on" or store_plaintext == "default":
                pwd_props = pwd_props | DOMAIN_PASSWORD_STORE_CLEARTEXT
                msgs.append("Plaintext password storage for changed passwords activated!")
            elif store_plaintext == "off":
                pwd_props = pwd_props & (~DOMAIN_PASSWORD_STORE_CLEARTEXT)
                msgs.append("Plaintext password storage for changed passwords deactivated!")

        if complexity is not None or store_plaintext is not None:
            m["pwdProperties"] = ldb.MessageElement(str(pwd_props),
                                                    ldb.FLAG_MOD_REPLACE, "pwdProperties")

        if history_length is not None:
            if history_length == "default":
                pwd_hist_len = 24
            else:
                pwd_hist_len = int(history_length)

            if pwd_hist_len < 0 or pwd_hist_len > 24:
                raise CommandError("Password history length must be in the range of 0 to 24!")

            m["pwdHistoryLength"] = ldb.MessageElement(str(pwd_hist_len),
                                                       ldb.FLAG_MOD_REPLACE, "pwdHistoryLength")
            msgs.append("Password history length changed!")

        if min_pwd_length is not None:
            if min_pwd_length == "default":
                min_pwd_len = 7
            else:
                min_pwd_len = int(min_pwd_length)

            if min_pwd_len < 0 or min_pwd_len > 14:
                raise CommandError("Minimum password length must be in the range of 0 to 14!")

            m["minPwdLength"] = ldb.MessageElement(str(min_pwd_len),
                                                   ldb.FLAG_MOD_REPLACE, "minPwdLength")
            msgs.append("Minimum password length changed!")

        if min_pwd_age is not None:
            if min_pwd_age == "default":
                min_pwd_age = 1
            else:
                min_pwd_age = int(min_pwd_age)

            if min_pwd_age < 0 or min_pwd_age > 998:
                raise CommandError("Minimum password age must be in the range of 0 to 998!")

            # days -> ticks
            min_pwd_age_ticks = -int(min_pwd_age * (24 * 60 * 60 * 1e7))

            m["minPwdAge"] = ldb.MessageElement(str(min_pwd_age_ticks),
                                                ldb.FLAG_MOD_REPLACE, "minPwdAge")
            msgs.append("Minimum password age changed!")

        if max_pwd_age is not None:
            if max_pwd_age == "default":
                max_pwd_age = 43
            else:
                max_pwd_age = int(max_pwd_age)

            if max_pwd_age < 0 or max_pwd_age > 999:
                raise CommandError("Maximum password age must be in the range of 0 to 999!")

            # days -> ticks
            if max_pwd_age == 0:
                max_pwd_age_ticks = NEVER_TIMESTAMP
            else:
                max_pwd_age_ticks = -int(max_pwd_age * (24 * 60 * 60 * 1e7))

            m["maxPwdAge"] = ldb.MessageElement(str(max_pwd_age_ticks),
                                                ldb.FLAG_MOD_REPLACE, "maxPwdAge")
            msgs.append("Maximum password age changed!")

        if account_lockout_duration is not None:
            if account_lockout_duration == "default":
                account_lockout_duration = 30
            else:
                account_lockout_duration = int(account_lockout_duration)

            if account_lockout_duration < 0 or account_lockout_duration > 99999:
                raise CommandError("Account lockout duration "
                                   "must be in the range of 0 to 99999!")

            # minutes -> ticks
            if account_lockout_duration == 0:
                account_lockout_duration_ticks = NEVER_TIMESTAMP
            else:
                account_lockout_duration_ticks = -int(account_lockout_duration * (60 * 1e7))

            m["lockoutDuration"] = ldb.MessageElement(str(account_lockout_duration_ticks),
                                                      ldb.FLAG_MOD_REPLACE, "lockoutDuration")
            msgs.append("Account lockout duration changed!")

        if account_lockout_threshold is not None:
            if account_lockout_threshold == "default":
                account_lockout_threshold = 0
            else:
                account_lockout_threshold = int(account_lockout_threshold)

            m["lockoutThreshold"] = ldb.MessageElement(str(account_lockout_threshold),
                                                       ldb.FLAG_MOD_REPLACE, "lockoutThreshold")
            msgs.append("Account lockout threshold changed!")

        if reset_account_lockout_after is not None:
            if reset_account_lockout_after == "default":
                reset_account_lockout_after = 30
            else:
                reset_account_lockout_after = int(reset_account_lockout_after)

            if reset_account_lockout_after < 0 or reset_account_lockout_after > 99999:
                raise CommandError("Maximum password age must be in the range of 0 to 99999!")

            # minutes -> ticks
            if reset_account_lockout_after == 0:
                reset_account_lockout_after_ticks = NEVER_TIMESTAMP
            else:
                reset_account_lockout_after_ticks = -int(reset_account_lockout_after * (60 * 1e7))

            m["lockOutObservationWindow"] = ldb.MessageElement(str(reset_account_lockout_after_ticks),
                                                               ldb.FLAG_MOD_REPLACE, "lockOutObservationWindow")
            msgs.append("Duration to reset account lockout after changed!")

        if max_pwd_age or min_pwd_age:
            # If we're setting either min or max password, make sure the max is
            # still greater overall. As either setting could be None, we use the
            # ticks here (which are always set) and work backwards.
            max_pwd_age = timestamp_to_days(max_pwd_age_ticks)
            min_pwd_age = timestamp_to_days(min_pwd_age_ticks)
            if max_pwd_age != 0 and min_pwd_age >= max_pwd_age:
                raise CommandError("Maximum password age (%d) must be greater than minimum password age (%d)!" % (max_pwd_age, min_pwd_age))

        if len(m) == 0:
            raise CommandError("You must specify at least one option to set. Try --help")
        samdb.modify(m)
        msgs.append("All changes applied successfully!")
        self.message("\n".join(msgs))


class cmd_domain_passwordsettings(SuperCommand):
    """Manage password policy settings."""

    subcommands = {}
    subcommands["pso"] = cmd_domain_passwordsettings_pso()
    subcommands["show"] = cmd_domain_passwordsettings_show()
    subcommands["set"] = cmd_domain_passwordsettings_set()
