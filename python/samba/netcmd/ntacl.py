# Manipulate file NT ACLs
#
# Copyright Matthieu Patou 2010 <mat@matws.net>
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

from samba.credentials import DONT_USE_KERBEROS
import samba.getopt as options
from samba.dcerpc import security, idmap
from samba.ntacls import setntacl, getntacl, getdosinfo
from samba import Ldb
from samba.ndr import ndr_unpack, ndr_print
from samba.samdb import SamDB
from samba.samba3 import param as s3param, passdb, smbd
from samba import provision
from samba.auth_util import system_session_unix
import os

from samba.auth import system_session

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)

def get_local_domain_sid(lp):
    is_ad_dc = False
    server_role = lp.server_role()
    if server_role == "ROLE_ACTIVE_DIRECTORY_DC":
        is_ad_dc = True

    s3conf = s3param.get_context()
    s3conf.load(lp.configfile)

    if is_ad_dc:
        try:
            samdb = SamDB(session_info=system_session(),
                          lp=lp)
        except Exception as e:
            raise CommandError("Unable to open samdb:", e)
        # ensure we are using the right samba_dsdb passdb backend, no
        # matter what
        s3conf.set("passdb backend", "samba_dsdb:%s" % samdb.url)

    try:
        if is_ad_dc:
            domain_sid = security.dom_sid(samdb.domain_sid)
        else:
            domain_sid = passdb.get_domain_sid()
    except:
        raise CommandError("Unable to read domain SID from configuration "
                           "files")
    return domain_sid


class cmd_ntacl_set(Command):
    """Set ACLs on a file."""

    synopsis = "%prog <acl> <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-q", "--quiet", help="Be quiet", action="store_true"),
        Option("--xattr-backend", type="choice", help="xattr backend type (native fs or tdb)",
               choices=["native", "tdb"]),
        Option("--eadb-file", help="Name of the tdb file where attributes are stored", type="string"),
        Option("--use-ntvfs", help="Set the ACLs directly to the TDB or xattr for use with the ntvfs file server", action="store_true"),
        Option("--use-s3fs", help="Set the ACLs for use with the default s3fs file server via the VFS layer", action="store_true"),
        Option("--service", help="Name of the smb.conf service to use when applying the ACLs", type="string")
    ]

    takes_args = ["acl", "file"]

    def run(self, acl, file, use_ntvfs=False, use_s3fs=False,
            quiet=False, xattr_backend=None, eadb_file=None,
            credopts=None, sambaopts=None, versionopts=None,
            service=None):
        logger = self.get_logger()
        lp = sambaopts.get_loadparm()
        domain_sid = get_local_domain_sid(lp)

        if not use_ntvfs and not use_s3fs:
            use_ntvfs = "smb" in lp.get("server services")
        elif use_s3fs:
            use_ntvfs = False

        setntacl(lp,
                 file,
                 acl,
                 str(domain_sid),
                 system_session_unix(),
                 xattr_backend,
                 eadb_file,
                 use_ntvfs=use_ntvfs,
                 service=service)

        if use_ntvfs:
            logger.warning("Please note that POSIX permissions have NOT been changed, only the stored NT ACL")


class cmd_dosinfo_get(Command):
    """Get DOS info of a file from xattr."""
    synopsis = "%prog <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_args = ["file"]

    def run(self, file, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        s3conf = s3param.get_context()
        s3conf.load(lp.configfile)

        dosinfo = getdosinfo(lp, file)
        if dosinfo:
            self.outf.write(ndr_print(dosinfo))


class cmd_ntacl_get(Command):
    """Get ACLs of a file."""
    synopsis = "%prog <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--as-sddl", help="Output ACL in the SDDL format", action="store_true"),
        Option("--xattr-backend", type="choice", help="xattr backend type (native fs or tdb)",
               choices=["native", "tdb"]),
        Option("--eadb-file", help="Name of the tdb file where attributes are stored", type="string"),
        Option("--use-ntvfs", help="Get the ACLs directly from the TDB or xattr used with the ntvfs file server", action="store_true"),
        Option("--use-s3fs", help="Get the ACLs for use via the VFS layer used by the default s3fs file server", action="store_true"),
        Option("--service", help="Name of the smb.conf service to use when getting the ACLs", type="string")
    ]

    takes_args = ["file"]

    def run(self, file, use_ntvfs=False, use_s3fs=False,
            as_sddl=False, xattr_backend=None, eadb_file=None,
            credopts=None, sambaopts=None, versionopts=None,
            service=None):
        lp = sambaopts.get_loadparm()
        domain_sid = get_local_domain_sid(lp)

        if not use_ntvfs and not use_s3fs:
            use_ntvfs = "smb" in lp.get("server services")
        elif use_s3fs:
            use_ntvfs = False

        acl = getntacl(lp,
                       file,
                       system_session_unix(),
                       xattr_backend,
                       eadb_file,
                       direct_db_access=use_ntvfs,
                       service=service)
        if as_sddl:
            self.outf.write(acl.as_sddl(domain_sid) + "\n")
        else:
            self.outf.write(ndr_print(acl))


class cmd_ntacl_changedomsid(Command):
    """Change the domain SID for ACLs"""
    synopsis = "%prog <Orig-Domain-SID> <New-Domain-SID> <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
    }

    takes_options = [
        Option(
            "--service",
            help="Name of the smb.conf service to use",
            type="string"),
        Option(
            "--use-ntvfs",
            help=("Set the ACLs directly to the TDB or xattr for use with the "
                  "ntvfs file server"),
            action="store_true"),
        Option(
            "--use-s3fs",
            help=("Set the ACLs for use with the default s3fs file server via "
                  "the VFS layer"),
            action="store_true"),
        Option(
            "--eadb-file",
            help="Name of the tdb file where attributes are stored",
            type="string"),
        Option(
            "--xattr-backend",
            type="choice",
            help="xattr backend type (native fs or tdb)",
            choices=["native", "tdb"]),
        Option(
            "-r",
            "--recursive",
            help="Set the ACLs for directories and their contents recursively",
            action="store_true"),
        Option(
            "--follow-symlinks",
            help="Follow symlinks",
            action="store_true"),
        Option(
            "-v",
            "--verbose",
            help="Be verbose",
            action="store_true"),
    ]

    takes_args = ["old_domain_sid", "new_domain_sid", "file"]

    def run(self,
            old_domain_sid_str,
            new_domain_sid_str,
            file,
            use_ntvfs=False,
            use_s3fs=False,
            service=None,
            xattr_backend=None,
            eadb_file=None,
            sambaopts=None,
            recursive=False,
            follow_symlinks=False,
            verbose=False):
        logger = self.get_logger()
        lp = sambaopts.get_loadparm()
        domain_sid = get_local_domain_sid(lp)

        if not use_ntvfs and not use_s3fs:
            use_ntvfs = "smb" in lp.get("server services")
        elif use_s3fs:
            use_ntvfs = False

        if not use_ntvfs and not service:
            raise CommandError(
                "Must provide a share name with --service=<share>")

        try:
            old_domain_sid = security.dom_sid(old_domain_sid_str)
        except Exception as e:
            raise CommandError("Could not parse old sid %s: %s" %
                               (old_domain_sid_str, e))

        try:
            new_domain_sid = security.dom_sid(new_domain_sid_str)
        except Exception as e:
            raise CommandError("Could not parse old sid %s: %s" %
                               (new_domain_sid_str, e))

        def changedom_sids(file):
            if verbose:
                self.outf.write("file: %s\n" % file)

            try:
                acl = getntacl(lp,
                               file,
                               system_session_unix(),
                               xattr_backend,
                               eadb_file,
                               direct_db_access=use_ntvfs,
                               service=service)
            except Exception as e:
                raise CommandError("Could not get acl for %s: %s" % (file, e))

            orig_sddl = acl.as_sddl(domain_sid)
            if verbose:
                self.outf.write("before:\n%s\n" % orig_sddl)

            def replace_domain_sid(sid):
                (dom, rid) = sid.split()
                if dom == old_domain_sid:
                    return security.dom_sid("%s-%i" % (new_domain_sid, rid))
                return sid

            acl.owner_sid = replace_domain_sid(acl.owner_sid)
            acl.group_sid = replace_domain_sid(acl.group_sid)

            if acl.sacl:
                for ace in acl.sacl.aces:
                    ace.trustee = replace_domain_sid(ace.trustee)
            if acl.dacl:
                for ace in acl.dacl.aces:
                    ace.trustee = replace_domain_sid(ace.trustee)

            new_sddl = acl.as_sddl(domain_sid)
            if verbose:
                self.outf.write("after:\n%s\n" % new_sddl)

            if orig_sddl == new_sddl:
                if verbose:
                    self.outf.write("nothing to do\n")
                return True

            try:
                setntacl(lp,
                         file,
                         acl,
                         new_domain_sid,
                         system_session_unix(),
                         xattr_backend,
                         eadb_file,
                         use_ntvfs=use_ntvfs,
                         service=service)
            except Exception as e:
                raise CommandError("Could not set acl for %s: %s" % (file, e))

        def recursive_changedom_sids(file):
            for root, dirs, files in os.walk(file, followlinks=follow_symlinks):
                for f in files:
                    changedom_sids(os.path.join(root, f))

                for d in dirs:
                    changedom_sids(os.path.join(root, d))

        changedom_sids(file)
        if recursive and os.path.isdir(file):
            recursive_changedom_sids(file)

        if use_ntvfs:
            logger.warning("Please note that POSIX permissions have NOT been "
                           "changed, only the stored NT ACL.")


class cmd_ntacl_sysvolreset(Command):
    """Reset sysvol ACLs to defaults (including correct ACLs on GPOs)."""
    synopsis = "%prog <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--use-ntvfs", help="Set the ACLs for use with the ntvfs file server", action="store_true"),
        Option("--use-s3fs", help="Set the ACLs for use with the default s3fs file server", action="store_true")
    ]

    def run(self, use_ntvfs=False, use_s3fs=False,
            credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        creds.set_kerberos_state(DONT_USE_KERBEROS)
        logger = self.get_logger()

        netlogon = lp.get("path", "netlogon")
        sysvol = lp.get("path", "sysvol")
        try:
            samdb = SamDB(session_info=system_session(),
                          lp=lp)
        except Exception as e:
            raise CommandError("Unable to open samdb:", e)

        if not use_ntvfs and not use_s3fs:
            use_ntvfs = "smb" in lp.get("server services")
        elif use_s3fs:
            use_ntvfs = False

        domain_sid = security.dom_sid(samdb.domain_sid)

        s3conf = s3param.get_context()
        s3conf.load(lp.configfile)
        # ensure we are using the right samba_dsdb passdb backend, no matter what
        s3conf.set("passdb backend", "samba_dsdb:%s" % samdb.url)

        LA_sid = security.dom_sid(str(domain_sid)
                                  + "-" + str(security.DOMAIN_RID_ADMINISTRATOR))
        BA_sid = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)

        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))

        # These assertions correct for current ad_dc selftest
        # configuration.  When other environments have a broad range of
        # groups mapped via passdb, we can relax some of these checks
        (LA_uid, LA_type) = s4_passdb.sid_to_id(LA_sid)
        if (LA_type != idmap.ID_TYPE_UID and LA_type != idmap.ID_TYPE_BOTH):
            raise CommandError("SID %s is not mapped to a UID" % LA_sid)
        (BA_gid, BA_type) = s4_passdb.sid_to_id(BA_sid)
        if (BA_type != idmap.ID_TYPE_GID and BA_type != idmap.ID_TYPE_BOTH):
            raise CommandError("SID %s is not mapped to a GID" % BA_sid)

        if use_ntvfs:
            logger.warning("Please note that POSIX permissions have NOT been changed, only the stored NT ACL")

        provision.setsysvolacl(samdb, netlogon, sysvol,
                               LA_uid, BA_gid, domain_sid,
                               lp.get("realm").lower(), samdb.domain_dn(),
                               lp, use_ntvfs=use_ntvfs)


class cmd_ntacl_sysvolcheck(Command):
    """Check sysvol ACLs match defaults (including correct ACLs on GPOs)."""
    synopsis = "%prog <file> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        creds.set_kerberos_state(DONT_USE_KERBEROS)
        logger = self.get_logger()

        netlogon = lp.get("path", "netlogon")
        sysvol = lp.get("path", "sysvol")
        try:
            samdb = SamDB(session_info=system_session(), lp=lp)
        except Exception as e:
            raise CommandError("Unable to open samdb:", e)

        domain_sid = security.dom_sid(samdb.domain_sid)

        provision.checksysvolacl(samdb, netlogon, sysvol,
                                 domain_sid,
                                 lp.get("realm").lower(), samdb.domain_dn(),
                                 lp)


class cmd_ntacl(SuperCommand):
    """NT ACLs manipulation."""

    subcommands = {}
    subcommands["set"] = cmd_ntacl_set()
    subcommands["get"] = cmd_ntacl_get()
    subcommands["changedomsid"] = cmd_ntacl_changedomsid()
    subcommands["sysvolreset"] = cmd_ntacl_sysvolreset()
    subcommands["sysvolcheck"] = cmd_ntacl_sysvolcheck()
    subcommands["getdosinfo"] = cmd_dosinfo_get()
