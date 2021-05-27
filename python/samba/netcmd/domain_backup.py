# domain_backup
#
# Copyright Andrew Bartlett <abartlet@samba.org>
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
import datetime
import os
import sys
import tarfile
import logging
import shutil
import tempfile
import samba
import tdb
import samba.getopt as options
from samba.samdb import SamDB, get_default_backend_store
import ldb
from ldb import LdbError
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba.ntacls import backup_online, backup_restore, backup_offline
from samba.auth import system_session
from samba.join import DCJoinContext, join_clone, DCCloneAndRenameContext
from samba.dcerpc.security import dom_sid
from samba.netcmd import Option, CommandError
from samba.dcerpc import misc, security, drsblobs
from samba import Ldb
from . fsmo import cmd_fsmo_seize
from samba.provision import make_smbconf, DEFAULTSITE
from samba.upgradehelpers import update_krbtgt_account_password
from samba.remove_dc import remove_dc
from samba.provision import secretsdb_self_join
from samba.dbchecker import dbcheck
import re
from samba.provision import guess_names, determine_host_ip, determine_host_ip6
from samba.provision.sambadns import (fill_dns_data_partitions,
                                      get_dnsadmins_sid,
                                      get_domainguid)
from samba.tdb_util import tdb_copy
from samba.mdb_util import mdb_copy
import errno
from subprocess import CalledProcessError
from samba import sites
from samba.dsdb import _dsdb_load_udv_v2
from samba.ndr import ndr_pack


# work out a SID (based on a free RID) to use when the domain gets restored.
# This ensures that the restored DC's SID won't clash with any other RIDs
# already in use in the domain
def get_sid_for_restore(samdb, logger):
    # Allocate a new RID without modifying the database. This should be safe,
    # because we acquire the RID master role after creating an account using
    # this RID during the restore process. Acquiring the RID master role
    # creates a new RID pool which we will fetch RIDs from, so we shouldn't get
    # duplicates.
    try:
        rid = samdb.next_free_rid()
    except LdbError as err:
        logger.info("A SID could not be allocated for restoring the domain. "
                    "Either no RID Set was found on this DC, "
                    "or the RID Set was not usable.")
        logger.info("To initialise this DC's RID pools, obtain a RID Set from "
                    "this domain's RID master, or run samba-tool dbcheck "
                    "to fix the existing RID Set.")
        raise CommandError("Cannot create backup", err)

    # Construct full SID
    sid = dom_sid(samdb.get_domain_sid())
    sid_for_restore = str(sid) + '-' + str(rid)

    # Confirm the SID is not already in use
    try:
        res = samdb.search(scope=ldb.SCOPE_BASE,
                           base='<SID=%s>' % sid_for_restore,
                           attrs=[],
                           controls=['show_deleted:1',
                                     'show_recycled:1'])
        if len(res) != 1:
            # This case makes no sense, but neither does a corrupt RID set
            raise CommandError("Cannot create backup - "
                               "this DC's RID pool is corrupt, "
                               "the next SID (%s) appears to be in use." %
                               sid_for_restore)
        raise CommandError("Cannot create backup - "
                           "this DC's RID pool is corrupt, "
                           "the next SID %s points to existing object %s. "
                           "Please run samba-tool dbcheck on the source DC." %
                           (sid_for_restore, res[0].dn))
    except ldb.LdbError as e:
        (enum, emsg) = e.args
        if enum != ldb.ERR_NO_SUCH_OBJECT:
            # We want NO_SUCH_OBJECT, anything else is a serious issue
            raise

    return str(sid) + '-' + str(rid)


def smb_sysvol_conn(server, lp, creds):
    """Returns an SMB connection to the sysvol share on the DC"""
    # the SMB bindings rely on having a s3 loadparm
    s3_lp = s3param.get_context()
    s3_lp.load(lp.configfile)
    return libsmb.Conn(server, "sysvol", lp=s3_lp, creds=creds, sign=True)


def get_timestamp():
    return datetime.datetime.now().isoformat().replace(':', '-')


def backup_filepath(targetdir, name, time_str):
    filename = 'samba-backup-%s-%s.tar.bz2' % (name, time_str)
    return os.path.join(targetdir, filename)


def create_backup_tar(logger, tmpdir, backup_filepath):
    # Adds everything in the tmpdir into a new tar file
    logger.info("Creating backup file %s..." % backup_filepath)
    tf = tarfile.open(backup_filepath, 'w:bz2')
    tf.add(tmpdir, arcname='./')
    tf.close()


def create_log_file(targetdir, lp, backup_type, server, include_secrets,
                    extra_info=None):
    # create a summary file about the backup, which will get included in the
    # tar file. This makes it easy for users to see what the backup involved,
    # without having to untar the DB and interrogate it
    f = open(os.path.join(targetdir, "backup.txt"), 'w')
    try:
        time_str = datetime.datetime.now().strftime('%Y-%b-%d %H:%M:%S')
        f.write("Backup created %s\n" % time_str)
        f.write("Using samba-tool version: %s\n" % lp.get('server string'))
        f.write("Domain %s backup, using DC '%s'\n" % (backup_type, server))
        f.write("Backup for domain %s (NetBIOS), %s (DNS realm)\n" %
                (lp.get('workgroup'), lp.get('realm').lower()))
        f.write("Backup contains domain secrets: %s\n" % str(include_secrets))
        if extra_info:
            f.write("%s\n" % extra_info)
    finally:
        f.close()


# Add a backup-specific marker to the DB with info that we'll use during
# the restore process
def add_backup_marker(samdb, marker, value):
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "@SAMBA_DSDB")
    m[marker] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, marker)
    samdb.modify(m)


def check_targetdir(logger, targetdir):
    if targetdir is None:
        raise CommandError('Target directory required')

    if not os.path.exists(targetdir):
        logger.info('Creating targetdir %s...' % targetdir)
        os.makedirs(targetdir)
    elif not os.path.isdir(targetdir):
        raise CommandError("%s is not a directory" % targetdir)


# For '--no-secrets' backups, this sets the Administrator user's password to a
# randomly-generated value. This is similar to the provision behaviour
def set_admin_password(logger, samdb):
    """Sets a randomly generated password for the backup DB's admin user"""

    # match the admin user by RID
    domainsid = samdb.get_domain_sid()
    match_admin = "(objectsid=%s-%s)" % (domainsid,
                                         security.DOMAIN_RID_ADMINISTRATOR)
    search_expr = "(&(objectClass=user)%s)" % (match_admin,)

    # retrieve the admin username (just in case it's been renamed)
    res = samdb.search(base=samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                       expression=search_expr)
    username = str(res[0]['samaccountname'])

    adminpass = samba.generate_random_password(12, 32)
    logger.info("Setting %s password in backup to: %s" % (username, adminpass))
    logger.info("Run 'samba-tool user setpassword %s' after restoring DB" %
                username)
    samdb.setpassword(search_expr, adminpass, force_change_at_next_login=False,
                      username=username)


class cmd_domain_backup_online(samba.netcmd.Command):
    '''Copy a running DC's current DB into a backup tar file.

    Takes a backup copy of the current domain from a running DC. If the domain
    were to undergo a catastrophic failure, then the backup file can be used to
    recover the domain. The backup created is similar to the DB that a new DC
    would receive when it joins the domain.

    Note that:
    - it's recommended to run 'samba-tool dbcheck' before taking a backup-file
      and fix any errors it reports.
    - all the domain's secrets are included in the backup file.
    - although the DB contents can be untarred and examined manually, you need
      to run 'samba-tool domain backup restore' before you can start a Samba DC
      from the backup file.'''

    synopsis = "%prog --server=<DC-to-backup> --targetdir=<output-dir>"
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="The DC to backup", type=str),
        Option("--targetdir", type=str,
               help="Directory to write the backup file to"),
        Option("--no-secrets", action="store_true", default=False,
               help="Exclude secret values from the backup created"),
        Option("--backend-store", type="choice", metavar="BACKENDSTORE",
               choices=["tdb", "mdb"],
               help="Specify the database backend to be used "
               "(default is %s)" % get_default_backend_store()),
    ]

    def run(self, sambaopts=None, credopts=None, server=None, targetdir=None,
            no_secrets=False, backend_store=None):
        logger = self.get_logger()
        logger.setLevel(logging.DEBUG)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # Make sure we have all the required args.
        if server is None:
            raise CommandError('Server required')

        check_targetdir(logger, targetdir)

        tmpdir = tempfile.mkdtemp(dir=targetdir)

        # Run a clone join on the remote
        include_secrets = not no_secrets
        try:
            ctx = join_clone(logger=logger, creds=creds, lp=lp,
                             include_secrets=include_secrets, server=server,
                             dns_backend='SAMBA_INTERNAL', targetdir=tmpdir,
                             backend_store=backend_store)

            # get the paths used for the clone, then drop the old samdb connection
            paths = ctx.paths
            del ctx

            # Get a free RID to use as the new DC's SID (when it gets restored)
            remote_sam = SamDB(url='ldap://' + server, credentials=creds,
                               session_info=system_session(), lp=lp)
            new_sid = get_sid_for_restore(remote_sam, logger)
            realm = remote_sam.domain_dns_name()

            # Grab the remote DC's sysvol files and bundle them into a tar file
            logger.info("Backing up sysvol files (via SMB)...")
            sysvol_tar = os.path.join(tmpdir, 'sysvol.tar.gz')
            smb_conn = smb_sysvol_conn(server, lp, creds)
            backup_online(smb_conn, sysvol_tar, remote_sam.get_domain_sid())

            # remove the default sysvol files created by the clone (we want to
            # make sure we restore the sysvol.tar.gz files instead)
            shutil.rmtree(paths.sysvol)

            # Edit the downloaded sam.ldb to mark it as a backup
            samdb = SamDB(url=paths.samdb, session_info=system_session(), lp=lp,
                          flags=ldb.FLG_DONT_CREATE_DB)
            time_str = get_timestamp()
            add_backup_marker(samdb, "backupDate", time_str)
            add_backup_marker(samdb, "sidForRestore", new_sid)
            add_backup_marker(samdb, "backupType", "online")

            # ensure the admin user always has a password set (same as provision)
            if no_secrets:
                set_admin_password(logger, samdb)

            # Add everything in the tmpdir to the backup tar file
            backup_file = backup_filepath(targetdir, realm, time_str)
            create_log_file(tmpdir, lp, "online", server, include_secrets)
            create_backup_tar(logger, tmpdir, backup_file)
        finally:
            shutil.rmtree(tmpdir)


class cmd_domain_backup_restore(cmd_fsmo_seize):
    '''Restore the domain's DB from a backup-file.

    This restores a previously backed up copy of the domain's DB on a new DC.

    Note that the restored DB will not contain the original DC that the backup
    was taken from (or any other DCs in the original domain). Only the new DC
    (specified by --newservername) will be present in the restored DB.

    Samba can then be started against the restored DB. Any existing DCs for the
    domain should be shutdown before the new DC is started. Other DCs can then
    be joined to the new DC to recover the network.

    Note that this command should be run as the root user - it will fail
    otherwise.'''

    synopsis = ("%prog --backup-file=<tar-file> --targetdir=<output-dir> "
                "--newservername=<DC-name>")
    takes_options = [
        Option("--backup-file", help="Path to backup file", type=str),
        Option("--targetdir", help="Path to write to", type=str),
        Option("--newservername", help="Name for new server", type=str),
        Option("--host-ip", type="string", metavar="IPADDRESS",
               help="set IPv4 ipaddress"),
        Option("--host-ip6", type="string", metavar="IP6ADDRESS",
               help="set IPv6 ipaddress"),
        Option("--site", help="Site to add the new server in", type=str),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def register_dns_zone(self, logger, samdb, lp, ntdsguid, host_ip,
                          host_ip6, site):
        '''
        Registers the new realm's DNS objects when a renamed domain backup
        is restored.
        '''
        names = guess_names(lp)
        domaindn = names.domaindn
        forestdn = samdb.get_root_basedn().get_linearized()
        dnsdomain = names.dnsdomain.lower()
        dnsforest = dnsdomain
        hostname = names.netbiosname.lower()
        domainsid = dom_sid(samdb.get_domain_sid())
        dnsadmins_sid = get_dnsadmins_sid(samdb, domaindn)
        domainguid = get_domainguid(samdb, domaindn)

        # work out the IP address to use for the new DC's DNS records
        host_ip = determine_host_ip(logger, lp, host_ip)
        host_ip6 = determine_host_ip6(logger, lp, host_ip6)

        if host_ip is None and host_ip6 is None:
            raise CommandError('Please specify a host-ip for the new server')

        logger.info("DNS realm was renamed to %s" % dnsdomain)
        logger.info("Populating DNS partitions for new realm...")

        # Add the DNS objects for the new realm (note: the backup clone already
        # has the root server objects, so don't add them again)
        fill_dns_data_partitions(samdb, domainsid, site, domaindn,
                                 forestdn, dnsdomain, dnsforest, hostname,
                                 host_ip, host_ip6, domainguid, ntdsguid,
                                 dnsadmins_sid, add_root=False)

    def fix_old_dc_references(self, samdb):
        '''Fixes attributes that reference the old/removed DCs'''

        # we just want to fix up DB problems here that were introduced by us
        # removing the old DCs. We restrict what we fix up so that the restored
        # DB matches the backed-up DB as close as possible. (There may be other
        # DB issues inherited from the backed-up DC, but it's not our place to
        # silently try to fix them here).
        samdb.transaction_start()
        chk = dbcheck(samdb, quiet=True, fix=True, yes=False,
                      in_transaction=True)

        # fix up stale references to the old DC
        setattr(chk, 'fix_all_old_dn_string_component_mismatch', 'ALL')
        attrs = ['lastKnownParent', 'interSiteTopologyGenerator']

        # fix-up stale one-way links that point to the old DC
        setattr(chk, 'remove_plausible_deleted_DN_links', 'ALL')
        attrs += ['msDS-NC-Replica-Locations']

        cross_ncs_ctrl = 'search_options:1:2'
        controls = ['show_deleted:1', cross_ncs_ctrl]
        chk.check_database(controls=controls, attrs=attrs)
        samdb.transaction_commit()

    def create_default_site(self, samdb, logger):
        '''Creates the default site, if it doesn't already exist'''

        sitename = DEFAULTSITE
        search_expr = "(&(cn={0})(objectclass=site))".format(sitename)
        res = samdb.search(samdb.get_config_basedn(), scope=ldb.SCOPE_SUBTREE,
                           expression=search_expr)

        if len(res) == 0:
            logger.info("Creating default site '{0}'".format(sitename))
            sites.create_site(samdb, samdb.get_config_basedn(), sitename)

        return sitename

    def remove_backup_markers(self, samdb):
        """Remove DB markers added by the backup process"""

        # check what markers we need to remove (this may vary)
        markers = ['sidForRestore', 'backupRename', 'backupDate', 'backupType']
        res = samdb.search(base=ldb.Dn(samdb, "@SAMBA_DSDB"),
                           scope=ldb.SCOPE_BASE,
                           attrs=markers)

        # remove any markers that exist in the DB
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, "@SAMBA_DSDB")

        for attr in markers:
            if attr in res[0]:
                m[attr] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, attr)

        samdb.modify(m)

    def get_backup_type(self, samdb):
        res = samdb.search(base=ldb.Dn(samdb, "@SAMBA_DSDB"),
                           scope=ldb.SCOPE_BASE,
                           attrs=['backupRename', 'backupType'])

        # note that the backupType marker won't exist on backups created on
        # v4.9. However, we can still infer the type, as only rename and
        # online backups are supported on v4.9
        if 'backupType' in res[0]:
            backup_type = str(res[0]['backupType'])
        elif 'backupRename' in res[0]:
            backup_type = "rename"
        else:
            backup_type = "online"

        return backup_type

    def save_uptodate_vectors(self, samdb, partitions):
        """Ensures the UTDV used by DRS is correct after an offline backup"""
        for nc in partitions:
            # load the replUpToDateVector we *should* have
            utdv = _dsdb_load_udv_v2(samdb, nc)

            # convert it to NDR format and write it into the DB
            utdv_blob = drsblobs.replUpToDateVectorBlob()
            utdv_blob.version = 2
            utdv_blob.ctr.cursors = utdv
            utdv_blob.ctr.count = len(utdv)
            new_value = ndr_pack(utdv_blob)

            m = ldb.Message()
            m.dn = ldb.Dn(samdb, nc)
            m["replUpToDateVector"] = ldb.MessageElement(new_value,
                                                         ldb.FLAG_MOD_REPLACE,
                                                         "replUpToDateVector")
            samdb.modify(m)

    def run(self, sambaopts=None, credopts=None, backup_file=None,
            targetdir=None, newservername=None, host_ip=None, host_ip6=None,
            site=None):
        if not (backup_file and os.path.exists(backup_file)):
            raise CommandError('Backup file not found.')
        if targetdir is None:
            raise CommandError('Please specify a target directory')
        # allow restoredc to install into a directory prepopulated by selftest
        if (os.path.exists(targetdir) and os.listdir(targetdir) and
            os.environ.get('SAMBA_SELFTEST') != '1'):
            raise CommandError('Target directory is not empty')
        if not newservername:
            raise CommandError('Server name required')

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler(sys.stdout))

        # ldapcmp prefers the server's netBIOS name in upper-case
        newservername = newservername.upper()

        # extract the backup .tar to a temp directory
        targetdir = os.path.abspath(targetdir)
        tf = tarfile.open(backup_file)
        tf.extractall(targetdir)
        tf.close()

        # use the smb.conf that got backed up, by default (save what was
        # actually backed up, before we mess with it)
        smbconf = os.path.join(targetdir, 'etc', 'smb.conf')
        shutil.copyfile(smbconf, smbconf + ".orig")

        # if a smb.conf was specified on the cmd line, then use that instead
        cli_smbconf = sambaopts.get_loadparm_path()
        if cli_smbconf:
            logger.info("Using %s as restored domain's smb.conf" % cli_smbconf)
            shutil.copyfile(cli_smbconf, smbconf)

        lp = samba.param.LoadParm()
        lp.load(smbconf)

        # open a DB connection to the restored DB
        private_dir = os.path.join(targetdir, 'private')
        samdb_path = os.path.join(private_dir, 'sam.ldb')
        samdb = SamDB(url=samdb_path, session_info=system_session(), lp=lp,
                      flags=ldb.FLG_DONT_CREATE_DB)
        backup_type = self.get_backup_type(samdb)

        if site is None:
            # There's no great way to work out the correct site to add the
            # restored DC to. By default, add it to Default-First-Site-Name,
            # creating the site if it doesn't already exist
            site = self.create_default_site(samdb, logger)
            logger.info("Adding new DC to site '{0}'".format(site))

        # read the naming contexts out of the DB
        res = samdb.search(base="", scope=ldb.SCOPE_BASE,
                           attrs=['namingContexts'])
        ncs = [str(r) for r in res[0].get('namingContexts')]

        # for offline backups we need to make sure the upToDateness info
        # contains the invocation-ID and highest-USN of the DC we backed up.
        # Otherwise replication propagation dampening won't correctly filter
        # objects created by that DC
        if backup_type == "offline":
            self.save_uptodate_vectors(samdb, ncs)

        # Create account using the join_add_objects function in the join object
        # We need namingContexts, account control flags, and the sid saved by
        # the backup process.
        creds = credopts.get_credentials(lp)
        ctx = DCJoinContext(logger, creds=creds, lp=lp, site=site,
                            forced_local_samdb=samdb,
                            netbios_name=newservername)
        ctx.nc_list = ncs
        ctx.full_nc_list = ncs
        ctx.userAccountControl = (samba.dsdb.UF_SERVER_TRUST_ACCOUNT |
                                  samba.dsdb.UF_TRUSTED_FOR_DELEGATION)

        # rewrite the smb.conf to make sure it uses the new targetdir settings.
        # (This doesn't update all filepaths in a customized config, but it
        # corrects the same paths that get set by a new provision)
        logger.info('Updating basic smb.conf settings...')
        make_smbconf(smbconf, newservername, ctx.domain_name,
                     ctx.realm, targetdir, lp=lp,
                     serverrole="active directory domain controller")

        # Get the SID saved by the backup process and create account
        res = samdb.search(base=ldb.Dn(samdb, "@SAMBA_DSDB"),
                           scope=ldb.SCOPE_BASE,
                           attrs=['sidForRestore'])
        sid = res[0].get('sidForRestore')[0]
        logger.info('Creating account with SID: ' + str(sid))
        try:
            ctx.join_add_objects(specified_sid=dom_sid(str(sid)))
        except LdbError as e:
            (enum, emsg) = e.args
            if enum != ldb.ERR_CONSTRAINT_VIOLATION:
                raise

            dup_res = []
            try:
                dup_res = samdb.search(base=ldb.Dn(samdb, "<SID=%s>" % sid),
                                       scope=ldb.SCOPE_BASE,
                                       attrs=['objectGUID'],
                                       controls=["show_deleted:0",
                                                 "show_recycled:0"])
            except LdbError as dup_e:
                (dup_enum, _) = dup_e.args
                if dup_enum != ldb.ERR_NO_SUCH_OBJECT:
                    raise

            if (len(dup_res) != 1):
                raise

            objectguid = samdb.schema_format_value("objectGUID",
                                                       dup_res[0]["objectGUID"][0])
            objectguid = objectguid.decode('utf-8')
            logger.error("The RID Pool on the source DC for the backup in %s "
                         "may be corrupt "
                         "or in conflict with SIDs already allocated "
                         "in the domain. " % backup_file)
            logger.error("Running 'samba-tool dbcheck' on the source "
                         "DC (and obtaining a new backup) may correct the issue.")
            logger.error("Alternatively please obtain a new backup "
                         "against a different DC.")
            logger.error("The SID we wish to use (%s) is recorded in "
                         "@SAMBA_DSDB as the sidForRestore attribute."
                         % sid)

            raise CommandError("Domain restore failed because there "
                               "is already an existing object (%s) "
                               "with SID %s and objectGUID %s.  "
                               "This conflicts with "
                               "the new DC account we want to add "
                               "for the restored domain.   " % (
                                dup_res[0].dn, sid, objectguid))

        m = ldb.Message()
        m.dn = ldb.Dn(samdb, '@ROOTDSE')
        ntds_guid = str(ctx.ntds_guid)
        m["dsServiceName"] = ldb.MessageElement("<GUID=%s>" % ntds_guid,
                                                ldb.FLAG_MOD_REPLACE,
                                                "dsServiceName")
        samdb.modify(m)

        # if we renamed the backed-up domain, then we need to add the DNS
        # objects for the new realm (we do this in the restore, now that we
        # know the new DC's IP address)
        if backup_type == "rename":
            self.register_dns_zone(logger, samdb, lp, ctx.ntds_guid,
                                   host_ip, host_ip6, site)

        secrets_path = os.path.join(private_dir, 'secrets.ldb')
        secrets_ldb = Ldb(secrets_path, session_info=system_session(), lp=lp,
                          flags=ldb.FLG_DONT_CREATE_DB)
        secretsdb_self_join(secrets_ldb, domain=ctx.domain_name,
                            realm=ctx.realm, dnsdomain=ctx.dnsdomain,
                            netbiosname=ctx.myname, domainsid=ctx.domsid,
                            machinepass=ctx.acct_pass,
                            key_version_number=ctx.key_version_number,
                            secure_channel_type=misc.SEC_CHAN_BDC)

        # Seize DNS roles
        domain_dn = samdb.domain_dn()
        forest_dn = samba.dn_from_dns_name(samdb.forest_dns_name())
        domaindns_dn = ("CN=Infrastructure,DC=DomainDnsZones,", domain_dn)
        forestdns_dn = ("CN=Infrastructure,DC=ForestDnsZones,", forest_dn)
        for dn_prefix, dns_dn in [forestdns_dn, domaindns_dn]:
            if dns_dn not in ncs:
                continue
            full_dn = dn_prefix + dns_dn
            m = ldb.Message()
            m.dn = ldb.Dn(samdb, full_dn)
            m["fSMORoleOwner"] = ldb.MessageElement(samdb.get_dsServiceName(),
                                                    ldb.FLAG_MOD_REPLACE,
                                                    "fSMORoleOwner")
            samdb.modify(m)

        # Seize other roles
        for role in ['rid', 'pdc', 'naming', 'infrastructure', 'schema']:
            self.seize_role(role, samdb, force=True)

        # Get all DCs and remove them (this ensures these DCs cannot
        # replicate because they will not have a password)
        search_expr = "(&(objectClass=Server)(serverReference=*))"
        res = samdb.search(samdb.get_config_basedn(), scope=ldb.SCOPE_SUBTREE,
                           expression=search_expr)
        for m in res:
            cn = str(m.get('cn')[0])
            if cn != newservername:
                remove_dc(samdb, logger, cn)

        # Remove the repsFrom and repsTo from each NC to ensure we do
        # not try (and fail) to talk to the old DCs
        for nc in ncs:
            msg = ldb.Message()
            msg.dn = ldb.Dn(samdb, nc)

            msg["repsFrom"] = ldb.MessageElement([],
                                                 ldb.FLAG_MOD_REPLACE,
                                                 "repsFrom")
            msg["repsTo"] = ldb.MessageElement([],
                                               ldb.FLAG_MOD_REPLACE,
                                               "repsTo")
            samdb.modify(msg)

        # Update the krbtgt passwords twice, ensuring no tickets from
        # the old domain are valid
        update_krbtgt_account_password(samdb)
        update_krbtgt_account_password(samdb)

        # restore the sysvol directory from the backup tar file, including the
        # original NTACLs. Note that the backup_restore() will fail if not root
        sysvol_tar = os.path.join(targetdir, 'sysvol.tar.gz')
        dest_sysvol_dir = lp.get('path', 'sysvol')
        if not os.path.exists(dest_sysvol_dir):
            os.makedirs(dest_sysvol_dir)
        backup_restore(sysvol_tar, dest_sysvol_dir, samdb, smbconf)
        os.remove(sysvol_tar)

        # fix up any stale links to the old DCs we just removed
        logger.info("Fixing up any remaining references to the old DCs...")
        self.fix_old_dc_references(samdb)

        # Remove DB markers added by the backup process
        self.remove_backup_markers(samdb)

        logger.info("Backup file successfully restored to %s" % targetdir)
        logger.info("Please check the smb.conf settings are correct before "
                    "starting samba.")


class cmd_domain_backup_rename(samba.netcmd.Command):
    '''Copy a running DC's DB to backup file, renaming the domain in the process.

    Where <new-domain> is the new domain's NetBIOS name, and <new-dnsrealm> is
    the new domain's realm in DNS form.

    This is similar to 'samba-tool backup online' in that it clones the DB of a
    running DC. However, this option also renames all the domain entries in the
    DB. Renaming the domain makes it possible to restore and start a new Samba
    DC without it interfering with the existing Samba domain. In other words,
    you could use this option to clone your production samba domain and restore
    it to a separate pre-production environment that won't overlap or interfere
    with the existing production Samba domain.

    Note that:
    - it's recommended to run 'samba-tool dbcheck' before taking a backup-file
      and fix any errors it reports.
    - all the domain's secrets are included in the backup file.
    - although the DB contents can be untarred and examined manually, you need
      to run 'samba-tool domain backup restore' before you can start a Samba DC
      from the backup file.
    - GPO and sysvol information will still refer to the old realm and will
      need to be updated manually.
    - if you specify 'keep-dns-realm', then the DNS records will need updating
      in order to work (they will still refer to the old DC's IP instead of the
      new DC's address).
    - we recommend that you only use this option if you know what you're doing.
    '''

    synopsis = ("%prog <new-domain> <new-dnsrealm> --server=<DC-to-backup> "
                "--targetdir=<output-dir>")
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--server", help="The DC to backup", type=str),
        Option("--targetdir", help="Directory to write the backup file",
               type=str),
        Option("--keep-dns-realm", action="store_true", default=False,
               help="Retain the DNS entries for the old realm in the backup"),
        Option("--no-secrets", action="store_true", default=False,
               help="Exclude secret values from the backup created"),
        Option("--backend-store", type="choice", metavar="BACKENDSTORE",
               choices=["tdb", "mdb"],
               help="Specify the database backend to be used "
               "(default is %s)" % get_default_backend_store()),
    ]

    takes_args = ["new_domain_name", "new_dns_realm"]

    def update_dns_root(self, logger, samdb, old_realm, delete_old_dns):
        '''Updates dnsRoot for the partition objects to reflect the rename'''

        # lookup the crossRef objects that hold the old realm's dnsRoot
        partitions_dn = samdb.get_partitions_dn()
        res = samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL,
                           attrs=["dnsRoot"],
                           expression='(&(objectClass=crossRef)(dnsRoot=*))')
        new_realm = samdb.domain_dns_name()

        # go through and add the new realm
        for res_msg in res:
            # dnsRoot can be multi-valued, so only look for the old realm
            for dns_root in res_msg["dnsRoot"]:
                dns_root = str(dns_root)
                dn = res_msg.dn
                if old_realm in dns_root:
                    new_dns_root = re.sub('%s$' % old_realm, new_realm,
                                          dns_root)
                    logger.info("Adding %s dnsRoot to %s" % (new_dns_root, dn))

                    m = ldb.Message()
                    m.dn = dn
                    m["dnsRoot"] = ldb.MessageElement(new_dns_root,
                                                      ldb.FLAG_MOD_ADD,
                                                      "dnsRoot")
                    samdb.modify(m)

                    # optionally remove the dnsRoot for the old realm
                    if delete_old_dns:
                        logger.info("Removing %s dnsRoot from %s" % (dns_root,
                                                                     dn))
                        m["dnsRoot"] = ldb.MessageElement(dns_root,
                                                          ldb.FLAG_MOD_DELETE,
                                                          "dnsRoot")
                        samdb.modify(m)

    # Updates the CN=<domain>,CN=Partitions,CN=Configuration,... object to
    # reflect the domain rename
    def rename_domain_partition(self, logger, samdb, new_netbios_name):
        '''Renames the domain parition object and updates its nETBIOSName'''

        # lookup the crossRef object that holds the nETBIOSName (nCName has
        # already been updated by this point, but the netBIOS hasn't)
        base_dn = samdb.get_default_basedn()
        nc_name = ldb.binary_encode(str(base_dn))
        partitions_dn = samdb.get_partitions_dn()
        res = samdb.search(base=partitions_dn, scope=ldb.SCOPE_ONELEVEL,
                           attrs=["nETBIOSName"],
                           expression='ncName=%s' % nc_name)

        logger.info("Changing backup domain's NetBIOS name to %s" %
                    new_netbios_name)
        m = ldb.Message()
        m.dn = res[0].dn
        m["nETBIOSName"] = ldb.MessageElement(new_netbios_name,
                                              ldb.FLAG_MOD_REPLACE,
                                              "nETBIOSName")
        samdb.modify(m)

        # renames the object itself to reflect the change in domain
        new_dn = "CN=%s,%s" % (new_netbios_name, partitions_dn)
        logger.info("Renaming %s --> %s" % (res[0].dn, new_dn))
        samdb.rename(res[0].dn, new_dn, controls=['relax:0'])

    def delete_old_dns_zones(self, logger, samdb, old_realm):
        # remove the top-level DNS entries for the old realm
        basedn = samdb.get_default_basedn()
        dn = "DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s" % (old_realm, basedn)
        logger.info("Deleting old DNS zone %s" % dn)
        samdb.delete(dn, ["tree_delete:1"])

        forestdn = samdb.get_root_basedn().get_linearized()
        dn = "DC=_msdcs.%s,CN=MicrosoftDNS,DC=ForestDnsZones,%s" % (old_realm,
                                                                    forestdn)
        logger.info("Deleting old DNS zone %s" % dn)
        samdb.delete(dn, ["tree_delete:1"])

    def fix_old_dn_attributes(self, samdb):
        '''Fixes attributes (i.e. objectCategory) that still use the old DN'''

        samdb.transaction_start()
        # Just fix any mismatches in DN detected (leave any other errors)
        chk = dbcheck(samdb, quiet=True, fix=True, yes=False,
                      in_transaction=True)
        # fix up incorrect objectCategory/etc attributes
        setattr(chk, 'fix_all_old_dn_string_component_mismatch', 'ALL')
        cross_ncs_ctrl = 'search_options:1:2'
        controls = ['show_deleted:1', cross_ncs_ctrl]
        chk.check_database(controls=controls)
        samdb.transaction_commit()

    def run(self, new_domain_name, new_dns_realm, sambaopts=None,
            credopts=None, server=None, targetdir=None, keep_dns_realm=False,
            no_secrets=False, backend_store=None):
        logger = self.get_logger()
        logger.setLevel(logging.INFO)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # Make sure we have all the required args.
        if server is None:
            raise CommandError('Server required')

        check_targetdir(logger, targetdir)

        delete_old_dns = not keep_dns_realm

        new_dns_realm = new_dns_realm.lower()
        new_domain_name = new_domain_name.upper()

        new_base_dn = samba.dn_from_dns_name(new_dns_realm)
        logger.info("New realm for backed up domain: %s" % new_dns_realm)
        logger.info("New base DN for backed up domain: %s" % new_base_dn)
        logger.info("New domain NetBIOS name: %s" % new_domain_name)

        tmpdir = tempfile.mkdtemp(dir=targetdir)

        # setup a join-context for cloning the remote server
        include_secrets = not no_secrets
        ctx = DCCloneAndRenameContext(new_base_dn, new_domain_name,
                                      new_dns_realm, logger=logger,
                                      creds=creds, lp=lp,
                                      include_secrets=include_secrets,
                                      dns_backend='SAMBA_INTERNAL',
                                      server=server, targetdir=tmpdir,
                                      backend_store=backend_store)

        # sanity-check we're not "renaming" the domain to the same values
        old_domain = ctx.domain_name
        if old_domain == new_domain_name:
            shutil.rmtree(tmpdir)
            raise CommandError("Cannot use the current domain NetBIOS name.")

        old_realm = ctx.realm
        if old_realm == new_dns_realm:
            shutil.rmtree(tmpdir)
            raise CommandError("Cannot use the current domain DNS realm.")

        # do the clone/rename
        ctx.do_join()

        # get the paths used for the clone, then drop the old samdb connection
        del ctx.local_samdb
        paths = ctx.paths

        # get a free RID to use as the new DC's SID (when it gets restored)
        remote_sam = SamDB(url='ldap://' + server, credentials=creds,
                           session_info=system_session(), lp=lp)
        new_sid = get_sid_for_restore(remote_sam, logger)

        # Grab the remote DC's sysvol files and bundle them into a tar file.
        # Note we end up with 2 sysvol dirs - the original domain's files (that
        # use the old realm) backed here, as well as default files generated
        # for the new realm as part of the clone/join.
        sysvol_tar = os.path.join(tmpdir, 'sysvol.tar.gz')
        smb_conn = smb_sysvol_conn(server, lp, creds)
        backup_online(smb_conn, sysvol_tar, remote_sam.get_domain_sid())

        # connect to the local DB (making sure we use the new/renamed config)
        lp.load(paths.smbconf)
        samdb = SamDB(url=paths.samdb, session_info=system_session(), lp=lp,
                      flags=ldb.FLG_DONT_CREATE_DB)

        # Edit the cloned sam.ldb to mark it as a backup
        time_str = get_timestamp()
        add_backup_marker(samdb, "backupDate", time_str)
        add_backup_marker(samdb, "sidForRestore", new_sid)
        add_backup_marker(samdb, "backupRename", old_realm)
        add_backup_marker(samdb, "backupType", "rename")

        # fix up the DNS objects that are using the old dnsRoot value
        self.update_dns_root(logger, samdb, old_realm, delete_old_dns)

        # update the netBIOS name and the Partition object for the domain
        self.rename_domain_partition(logger, samdb, new_domain_name)

        if delete_old_dns:
            self.delete_old_dns_zones(logger, samdb, old_realm)

        logger.info("Fixing DN attributes after rename...")
        self.fix_old_dn_attributes(samdb)

        # ensure the admin user always has a password set (same as provision)
        if no_secrets:
            set_admin_password(logger, samdb)

        # Add everything in the tmpdir to the backup tar file
        backup_file = backup_filepath(targetdir, new_dns_realm, time_str)
        create_log_file(tmpdir, lp, "rename", server, include_secrets,
                        "Original domain %s (NetBIOS), %s (DNS realm)" %
                        (old_domain, old_realm))
        create_backup_tar(logger, tmpdir, backup_file)

        shutil.rmtree(tmpdir)


class cmd_domain_backup_offline(samba.netcmd.Command):
    '''Backup the local domain directories safely into a tar file.

    Takes a backup copy of the current domain from the local files on disk,
    with proper locking of the DB to ensure consistency. If the domain were to
    undergo a catastrophic failure, then the backup file can be used to recover
    the domain.

    An offline backup differs to an online backup in the following ways:
    - a backup can be created even if the DC isn't currently running.
    - includes non-replicated attributes that an online backup wouldn't store.
    - takes a copy of the raw database files, which has the risk that any
      hidden problems in the DB are preserved in the backup.'''

    synopsis = "%prog [options]"
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
    }

    takes_options = [
        Option("--targetdir",
               help="Output directory (required)",
               type=str),
    ]

    backup_ext = '.bak-offline'

    def offline_tdb_copy(self, path):
        backup_path = path + self.backup_ext
        try:
            tdb_copy(path, backup_path, readonly=True)
        except CalledProcessError as copy_err:
            # If the copy didn't work, check if it was caused by an EINVAL
            # error on opening the DB.  If so, it's a mutex locked database,
            # which we can safely ignore.
            try:
                tdb.open(path)
            except Exception as e:
                if hasattr(e, 'errno') and e.errno == errno.EINVAL:
                    return
                raise e
            raise copy_err
        if not os.path.exists(backup_path):
            s = "tdbbackup said backup succeeded but {0} not found"
            raise CommandError(s.format(backup_path))

    def offline_mdb_copy(self, path):
        mdb_copy(path, path + self.backup_ext)

    # Secrets databases are a special case: a transaction must be started
    # on the secrets.ldb file before backing up that file and secrets.tdb
    def backup_secrets(self, private_dir, lp, logger):
        secrets_path = os.path.join(private_dir, 'secrets')
        secrets_obj = Ldb(secrets_path + '.ldb', lp=lp,
                          flags=ldb.FLG_DONT_CREATE_DB)
        logger.info('Starting transaction on ' + secrets_path)
        secrets_obj.transaction_start()
        self.offline_tdb_copy(secrets_path + '.ldb')
        self.offline_tdb_copy(secrets_path + '.tdb')
        secrets_obj.transaction_cancel()

    # sam.ldb must have a transaction started on it before backing up
    # everything in sam.ldb.d with the appropriate backup function.
    def backup_smb_dbs(self, private_dir, samdb, lp, logger):
        # First, determine if DB backend is MDB.  Assume not unless there is a
        # 'backendStore' attribute on @PARTITION containing the text 'mdb'
        store_label = "backendStore"
        res = samdb.search(base="@PARTITION", scope=ldb.SCOPE_BASE,
                           attrs=[store_label])
        mdb_backend = store_label in res[0] and str(res[0][store_label][0]) == 'mdb'

        sam_ldb_path = os.path.join(private_dir, 'sam.ldb')
        copy_function = None
        if mdb_backend:
            logger.info('MDB backend detected.  Using mdb backup function.')
            copy_function = self.offline_mdb_copy
        else:
            logger.info('Starting transaction on ' + sam_ldb_path)
            copy_function = self.offline_tdb_copy
            sam_obj = Ldb(sam_ldb_path, lp=lp, flags=ldb.FLG_DONT_CREATE_DB)
            sam_obj.transaction_start()

        logger.info('   backing up ' + sam_ldb_path)
        self.offline_tdb_copy(sam_ldb_path)
        sam_ldb_d = sam_ldb_path + '.d'
        for sam_file in os.listdir(sam_ldb_d):
            sam_file = os.path.join(sam_ldb_d, sam_file)
            if sam_file.endswith('.ldb'):
                logger.info('   backing up locked/related file ' + sam_file)
                copy_function(sam_file)
            else:
                logger.info('   copying locked/related file ' + sam_file)
                shutil.copyfile(sam_file, sam_file + self.backup_ext)

        if not mdb_backend:
            sam_obj.transaction_cancel()

    # Find where a path should go in the fixed backup archive structure.
    def get_arc_path(self, path, conf_paths):
        backup_dirs = {"private": conf_paths.private_dir,
                       "statedir": conf_paths.state_dir,
                       "etc": os.path.dirname(conf_paths.smbconf)}
        matching_dirs = [(_, p) for (_, p) in backup_dirs.items() if
                         path.startswith(p)]
        arc_path, fs_path = matching_dirs[0]

        # If more than one directory is a parent of this path, then at least
        # one configured path is a subdir of another. Use closest match.
        if len(matching_dirs) > 1:
            arc_path, fs_path = max(matching_dirs, key=lambda p: len(p[1]))
        arc_path += path[len(fs_path):]

        return arc_path

    def run(self, sambaopts=None, targetdir=None):

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler(sys.stdout))

        # Get the absolute paths of all the directories we're going to backup
        lp = sambaopts.get_loadparm()

        paths = samba.provision.provision_paths_from_lp(lp, lp.get('realm'))
        if not (paths.samdb and os.path.exists(paths.samdb)):
            logger.error("No database found at {0}".format(paths.samdb))
            raise CommandError('Please check you are root, and ' +
                               'are running this command on an AD DC')

        check_targetdir(logger, targetdir)

        samdb = SamDB(url=paths.samdb, session_info=system_session(), lp=lp,
                      flags=ldb.FLG_RDONLY)
        sid = get_sid_for_restore(samdb, logger)

        # Iterating over the directories in this specific order ensures that
        # when the private directory contains hardlinks that are also contained
        # in other directories to be backed up (such as in paths.binddns_dir),
        # the hardlinks in the private directory take precedence.
        backup_dirs = [paths.private_dir, paths.state_dir,
                       os.path.dirname(paths.smbconf)]  # etc dir
        logger.info('running backup on dirs: {0}'.format(' '.join(backup_dirs)))

        # Recursively get all file paths in the backup directories
        all_files = []
        for backup_dir in backup_dirs:
            for (working_dir, _, filenames) in os.walk(backup_dir):
                if working_dir.startswith(paths.sysvol):
                    continue
                if working_dir.endswith('.sock') or '.sock/' in working_dir:
                    continue
                # The BIND DNS database can be regenerated, so it doesn't need
                # to be backed up.
                if working_dir.startswith(os.path.join(paths.binddns_dir, 'dns')):
                    continue

                for filename in filenames:
                    full_path = os.path.join(working_dir, filename)

                    # Ignore files that have already been added. This prevents
                    # duplicates if one backup dir is a subdirectory of another,
                    # or if backup dirs contain hardlinks.
                    if any(os.path.samefile(full_path, file) for file in all_files):
                        continue

                    # Assume existing backup files are from a previous backup.
                    # Delete and ignore.
                    if filename.endswith(self.backup_ext):
                        os.remove(full_path)
                        continue

                    # Sock files are autogenerated at runtime, ignore.
                    if filename.endswith('.sock'):
                        continue

                    all_files.append(full_path)

        # Backup secrets, sam.ldb and their downstream files
        self.backup_secrets(paths.private_dir, lp, logger)
        self.backup_smb_dbs(paths.private_dir, samdb, lp, logger)

        # Open the new backed up samdb, flag it as backed up, and write
        # the next SID so the restore tool can add objects.
        # WARNING: Don't change this code unless you know what you're doing.
        #          Writing to a .bak file only works because the DN being
        #          written to happens to be top level.
        samdb = SamDB(url=paths.samdb + self.backup_ext,
                      session_info=system_session(), lp=lp,
                      flags=ldb.FLG_DONT_CREATE_DB)
        time_str = get_timestamp()
        add_backup_marker(samdb, "backupDate", time_str)
        add_backup_marker(samdb, "sidForRestore", sid)
        add_backup_marker(samdb, "backupType", "offline")

        # Now handle all the LDB and TDB files that are not linked to
        # anything else.  Use transactions for LDBs.
        for path in all_files:
            if not os.path.exists(path + self.backup_ext):
                if path.endswith('.ldb'):
                    logger.info('Starting transaction on solo db: ' + path)
                    ldb_obj = Ldb(path, lp=lp, flags=ldb.FLG_DONT_CREATE_DB)
                    ldb_obj.transaction_start()
                    logger.info('   running tdbbackup on the same file')
                    self.offline_tdb_copy(path)
                    ldb_obj.transaction_cancel()
                elif path.endswith('.tdb'):
                    logger.info('running tdbbackup on lone tdb file ' + path)
                    self.offline_tdb_copy(path)

        # Now make the backup tar file and add all
        # backed up files and any other files to it.
        temp_tar_dir = tempfile.mkdtemp(dir=targetdir,
                                        prefix='INCOMPLETEsambabackupfile')
        temp_tar_name = os.path.join(temp_tar_dir, "samba-backup.tar.bz2")
        tar = tarfile.open(temp_tar_name, 'w:bz2')

        logger.info('running offline ntacl backup of sysvol')
        sysvol_tar_fn = 'sysvol.tar.gz'
        sysvol_tar = os.path.join(temp_tar_dir, sysvol_tar_fn)
        backup_offline(paths.sysvol, sysvol_tar, samdb, paths.smbconf)
        tar.add(sysvol_tar, sysvol_tar_fn)
        os.remove(sysvol_tar)

        create_log_file(temp_tar_dir, lp, "offline", "localhost", True)
        backup_fn = os.path.join(temp_tar_dir, "backup.txt")
        tar.add(backup_fn, os.path.basename(backup_fn))
        os.remove(backup_fn)

        logger.info('building backup tar')
        for path in all_files:
            arc_path = self.get_arc_path(path, paths)

            if os.path.exists(path + self.backup_ext):
                logger.info('   adding backup ' + arc_path + self.backup_ext +
                            ' to tar and deleting file')
                tar.add(path + self.backup_ext, arcname=arc_path)
                os.remove(path + self.backup_ext)
            elif path.endswith('.ldb') or path.endswith('.tdb'):
                logger.info('   skipping ' + arc_path)
            else:
                logger.info('   adding misc file ' + arc_path)
                tar.add(path, arcname=arc_path)

        tar.close()
        os.rename(temp_tar_name,
                  os.path.join(targetdir,
                               'samba-backup-{0}.tar.bz2'.format(time_str)))
        os.rmdir(temp_tar_dir)
        logger.info('Backup succeeded.')


class cmd_domain_backup(samba.netcmd.SuperCommand):
    '''Create or restore a backup of the domain.'''
    subcommands = {'offline': cmd_domain_backup_offline(),
                   'online': cmd_domain_backup_online(),
                   'rename': cmd_domain_backup_rename(),
                   'restore': cmd_domain_backup_restore()}
