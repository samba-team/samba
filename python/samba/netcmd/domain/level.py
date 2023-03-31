# domain management - domain level
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
from samba.dsdb import DS_DOMAIN_FUNCTION_2000
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB

from .common import level_to_string, string_to_level


class cmd_domain_level(Command):
    """Raise domain and forest function levels."""

    synopsis = "%prog (show|raise <options>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("--forest-level", type="choice", choices=["2003", "2008", "2008_R2", "2012", "2012_R2", "2016"],
               help="The forest function level (2003 | 2008 | 2008_R2 | 2012 | 2012_R2 | 2016)"),
        Option("--domain-level", type="choice", choices=["2003", "2008", "2008_R2", "2012", "2012_R2", "2016"],
               help="The domain function level (2003 | 2008 | 2008_R2 | 2012 | 2012_R2 | 2016)")
    ]

    takes_args = ["subcommand"]

    def run(self, subcommand, H=None, forest_level=None, domain_level=None,
            quiet=False, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()

        res_forest = samdb.search("CN=Partitions,%s" % samdb.get_config_basedn(),
                                  scope=ldb.SCOPE_BASE, attrs=["msDS-Behavior-Version"])
        assert len(res_forest) == 1

        res_domain = samdb.search(domain_dn, scope=ldb.SCOPE_BASE,
                                  attrs=["msDS-Behavior-Version", "nTMixedDomain"])
        assert len(res_domain) == 1

        res_dc_s = samdb.search("CN=Sites,%s" % samdb.get_config_basedn(),
                                scope=ldb.SCOPE_SUBTREE, expression="(objectClass=nTDSDSA)",
                                attrs=["msDS-Behavior-Version"])
        assert len(res_dc_s) >= 1

        # default values, since "msDS-Behavior-Version" does not exist on Windows 2000 AD
        level_forest = DS_DOMAIN_FUNCTION_2000
        level_domain = DS_DOMAIN_FUNCTION_2000

        if "msDS-Behavior-Version" in res_forest[0]:
            level_forest = int(res_forest[0]["msDS-Behavior-Version"][0])
        if "msDS-Behavior-Version" in res_domain[0]:
            level_domain = int(res_domain[0]["msDS-Behavior-Version"][0])
        level_domain_mixed = int(res_domain[0]["nTMixedDomain"][0])

        min_level_dc = None
        for msg in res_dc_s:
            if "msDS-Behavior-Version" in msg:
                if min_level_dc is None or int(msg["msDS-Behavior-Version"][0]) < min_level_dc:
                    min_level_dc = int(msg["msDS-Behavior-Version"][0])
            else:
                min_level_dc = DS_DOMAIN_FUNCTION_2000
                # well, this is the least
                break

        if level_forest < DS_DOMAIN_FUNCTION_2000 or level_domain < DS_DOMAIN_FUNCTION_2000:
            raise CommandError("Domain and/or forest function level(s) is/are invalid. Correct them or reprovision!")
        if min_level_dc < DS_DOMAIN_FUNCTION_2000:
            raise CommandError("Lowest function level of a DC is invalid. Correct this or reprovision!")
        if level_forest > level_domain:
            raise CommandError("Forest function level is higher than the domain level(s). Correct this or reprovision!")
        if level_domain > min_level_dc:
            raise CommandError("Domain function level is higher than the lowest function level of a DC. Correct this or reprovision!")

        if subcommand == "show":
            self.message("Domain and forest function level for domain '%s'" % domain_dn)
            if level_forest == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a forest function level lower than Windows 2000 (Native). This isn't supported! Please raise!")
            if level_domain == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a domain function level lower than Windows 2000 (Native). This isn't supported! Please raise!")
            if min_level_dc == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed != 0:
                self.message("\nATTENTION: You run SAMBA 4 on a lowest function level of a DC lower than Windows 2003. This isn't supported! Please step-up or upgrade the concerning DC(s)!")

            self.message("")

            outstr = level_to_string(level_forest)
            self.message("Forest function level: (Windows) " + outstr)

            if level_domain == DS_DOMAIN_FUNCTION_2000 and level_domain_mixed:
                outstr = "2000 mixed (NT4 DC support)"
            else:
                outstr = level_to_string(level_domain)
            self.message("Domain function level: (Windows) " + outstr)

            outstr = level_to_string(min_level_dc)
            self.message("Lowest function level of a DC: (Windows) " + outstr)

        elif subcommand == "raise":
            msgs = []

            if domain_level is not None:
                new_level_domain = string_to_level(domain_level)

                if new_level_domain <= level_domain and level_domain_mixed == 0:
                    raise CommandError("Domain function level can't be smaller than or equal to the actual one!")
                if new_level_domain > min_level_dc:
                    raise CommandError("Domain function level can't be higher than the lowest function level of a DC!")

                # Deactivate mixed/interim domain support
                if level_domain_mixed != 0:
                    # Directly on the base DN
                    m = ldb.Message()
                    m.dn = ldb.Dn(samdb, domain_dn)
                    m["nTMixedDomain"] = ldb.MessageElement("0",
                                                            ldb.FLAG_MOD_REPLACE, "nTMixedDomain")
                    samdb.modify(m)
                    # Under partitions
                    m = ldb.Message()
                    m.dn = ldb.Dn(samdb, "CN=" + lp.get("workgroup") + ",CN=Partitions,%s" % samdb.get_config_basedn())
                    m["nTMixedDomain"] = ldb.MessageElement("0",
                                                            ldb.FLAG_MOD_REPLACE, "nTMixedDomain")
                    try:
                        samdb.modify(m)
                    except ldb.LdbError as e:
                        (enum, emsg) = e.args
                        if enum != ldb.ERR_UNWILLING_TO_PERFORM:
                            raise

                # Directly on the base DN
                m = ldb.Message()
                m.dn = ldb.Dn(samdb, domain_dn)
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_domain), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                samdb.modify(m)
                # Under partitions
                m = ldb.Message()
                m.dn = ldb.Dn(samdb, "CN=" + lp.get("workgroup")
                              + ",CN=Partitions,%s" % samdb.get_config_basedn())
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_domain), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                try:
                    samdb.modify(m)
                except ldb.LdbError as e2:
                    (enum, emsg) = e2.args
                    if enum != ldb.ERR_UNWILLING_TO_PERFORM:
                        raise

                level_domain = new_level_domain
                msgs.append("Domain function level changed!")

            if forest_level is not None:
                new_level_forest = string_to_level(forest_level)

                if new_level_forest <= level_forest:
                    raise CommandError("Forest function level can't be smaller than or equal to the actual one!")
                if new_level_forest > level_domain:
                    raise CommandError("Forest function level can't be higher than the domain function level(s). Please raise it/them first!")

                m = ldb.Message()
                m.dn = ldb.Dn(samdb, "CN=Partitions,%s" % samdb.get_config_basedn())
                m["msDS-Behavior-Version"] = ldb.MessageElement(
                    str(new_level_forest), ldb.FLAG_MOD_REPLACE,
                    "msDS-Behavior-Version")
                samdb.modify(m)
                msgs.append("Forest function level changed!")
            msgs.append("All changes applied successfully!")
            self.message("\n".join(msgs))
        else:
            raise CommandError("invalid argument: '%s' (choose from 'show', 'raise')" % subcommand)
