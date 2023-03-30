# domain management - domain classicupgrade
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

import os
import tempfile
import subprocess

import samba
import samba.getopt as options
from samba.auth import system_session
from samba.auth_util import system_session_unix
from samba.common import get_string
from samba.netcmd import Command, CommandError, Option
from samba.samba3 import Samba3
from samba.samba3 import param as s3param
from samba.upgrade import upgrade_from_samba3

from .common import common_ntvfs_options


def get_testparm_var(testparm, smbconf, varname):
    errfile = open(os.devnull, 'w')
    p = subprocess.Popen([testparm, '-s', '-l',
                          '--parameter-name=%s' % varname, smbconf],
                         stdout=subprocess.PIPE, stderr=errfile)
    (out, err) = p.communicate()
    errfile.close()
    lines = out.split(b'\n')
    if lines:
        return get_string(lines[0]).strip()
    return ""


class cmd_domain_classicupgrade(Command):
    """Upgrade from Samba classic (NT4-like) database to Samba AD DC database.

    Specify either a directory with all Samba classic DC databases and state files (with --dbdir) or
    the testparm utility from your classic installation (with --testparm).
    """

    synopsis = "%prog [options] <classic_smb_conf>"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions
    }

    takes_options = [
        Option("--dbdir", type="string", metavar="DIR",
               help="Path to samba classic DC database directory"),
        Option("--testparm", type="string", metavar="PATH",
               help="Path to samba classic DC testparm utility from the previous installation.  This allows the default paths of the previous installation to be followed"),
        Option("--targetdir", type="string", metavar="DIR",
               help="Path prefix where the new Samba 4.0 AD domain should be initialised"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--dns-backend", type="choice", metavar="NAMESERVER-BACKEND",
               choices=["SAMBA_INTERNAL", "BIND9_FLATFILE", "BIND9_DLZ", "NONE"],
               help="The DNS server backend. SAMBA_INTERNAL is the builtin name server (default), "
               "BIND9_FLATFILE uses bind9 text database to store zone information, "
               "BIND9_DLZ uses samba4 AD to store zone information, "
               "NONE skips the DNS setup entirely (this DC will not be a DNS server)",
               default="SAMBA_INTERNAL")
    ]

    ntvfs_options = [
        Option("--use-xattrs", type="choice", choices=["yes", "no", "auto"],
               metavar="[yes|no|auto]",
               help="Define if we should use the native fs capabilities or a tdb file for "
               "storing attributes likes ntacl when --use-ntvfs is set. "
               "auto tries to make an inteligent guess based on the user rights and system capabilities",
               default="auto")
    ]
    if samba.is_ntvfs_fileserver_built():
        takes_options.extend(common_ntvfs_options)
        takes_options.extend(ntvfs_options)

    takes_args = ["smbconf"]

    def run(self, smbconf=None, targetdir=None, dbdir=None, testparm=None,
            quiet=False, verbose=False, use_xattrs="auto", sambaopts=None, versionopts=None,
            dns_backend=None, use_ntvfs=False):

        if not os.path.exists(smbconf):
            raise CommandError("File %s does not exist" % smbconf)

        if testparm and not os.path.exists(testparm):
            raise CommandError("Testparm utility %s does not exist" % testparm)

        if dbdir and not os.path.exists(dbdir):
            raise CommandError("Directory %s does not exist" % dbdir)

        if not dbdir and not testparm:
            raise CommandError("Please specify either dbdir or testparm")

        logger = self.get_logger(verbose=verbose, quiet=quiet)

        if dbdir and testparm:
            logger.warning("both dbdir and testparm specified, ignoring dbdir.")
            dbdir = None

        lp = sambaopts.get_loadparm()

        s3conf = s3param.get_context()

        if sambaopts.realm:
            s3conf.set("realm", sambaopts.realm)

        if targetdir is not None:
            if not os.path.isdir(targetdir):
                os.mkdir(targetdir)

        eadb = True
        if use_xattrs == "yes":
            eadb = False
        elif use_xattrs == "auto" and use_ntvfs == False:
            eadb = False
        elif use_ntvfs == False:
            raise CommandError("--use-xattrs=no requires --use-ntvfs (not supported for production use).  "
                               "Please re-run with --use-xattrs omitted.")
        elif use_xattrs == "auto" and not s3conf.get("posix:eadb"):
            if targetdir:
                tmpfile = tempfile.NamedTemporaryFile(dir=os.path.abspath(targetdir))
            else:
                tmpfile = tempfile.NamedTemporaryFile(dir=os.path.abspath(os.path.dirname(lp.get("private dir"))))
            try:
                try:
                    samba.ntacls.setntacl(lp, tmpfile.name,
                                          "O:S-1-5-32G:S-1-5-32",
                                          "S-1-5-32",
                                          system_session_unix(),
                                          "native")
                    eadb = False
                except Exception:
                    # FIXME: Don't catch all exceptions here
                    logger.info("You are not root or your system does not support xattr, using tdb backend for attributes. "
                                "If you intend to use this provision in production, rerun the script as root on a system supporting xattrs.")
            finally:
                tmpfile.close()

        # Set correct default values from dbdir or testparm
        paths = {}
        if dbdir:
            paths["state directory"] = dbdir
            paths["private dir"] = dbdir
            paths["lock directory"] = dbdir
            paths["smb passwd file"] = dbdir + "/smbpasswd"
        else:
            paths["state directory"] = get_testparm_var(testparm, smbconf, "state directory")
            paths["private dir"] = get_testparm_var(testparm, smbconf, "private dir")
            paths["smb passwd file"] = get_testparm_var(testparm, smbconf, "smb passwd file")
            paths["lock directory"] = get_testparm_var(testparm, smbconf, "lock directory")
            # "testparm" from Samba 3 < 3.4.x is not aware of the parameter
            # "state directory", instead make use of "lock directory"
            if len(paths["state directory"]) == 0:
                paths["state directory"] = paths["lock directory"]

        for p in paths:
            s3conf.set(p, paths[p])

        # load smb.conf parameters
        logger.info("Reading smb.conf")
        s3conf.load(smbconf)
        samba3 = Samba3(smbconf, s3conf)

        logger.info("Provisioning")
        upgrade_from_samba3(samba3, logger, targetdir, session_info=system_session(),
                            useeadb=eadb, dns_backend=dns_backend, use_ntvfs=use_ntvfs)
