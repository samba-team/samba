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
import samba.getopt as options
from samba.samdb import SamDB
import ldb
from samba import smb
from samba.ntacls import backup_online, backup_restore
from samba.auth import system_session
from samba.join import DCJoinContext, join_clone, DCCloneAndRenameContext
from samba.dcerpc.security import dom_sid
from samba.netcmd import Option, CommandError
from samba.dcerpc import misc, security
from samba import Ldb
from fsmo import cmd_fsmo_seize
from samba.provision import make_smbconf
from samba.upgradehelpers import update_krbtgt_account_password
from samba.remove_dc import remove_dc
from samba.provision import secretsdb_self_join
from samba.dbchecker import dbcheck
import re
from samba.provision import guess_names, determine_host_ip, determine_host_ip6
from samba.provision.sambadns import (fill_dns_data_partitions,
                                      get_dnsadmins_sid,
                                      get_domainguid)


# work out a SID (based on a free RID) to use when the domain gets restored.
# This ensures that the restored DC's SID won't clash with any other RIDs
# already in use in the domain
def get_sid_for_restore(samdb):
    # Find the DN of the RID set of the server
    res = samdb.search(base=ldb.Dn(samdb, samdb.get_serverName()),
                       scope=ldb.SCOPE_BASE, attrs=["serverReference"])
    server_ref_dn = ldb.Dn(samdb, res[0]['serverReference'][0])
    res = samdb.search(base=server_ref_dn,
                       scope=ldb.SCOPE_BASE,
                       attrs=['rIDSetReferences'])
    rid_set_dn = ldb.Dn(samdb, res[0]['rIDSetReferences'][0])

    # Get the alloc pools and next RID of the RID set
    res = samdb.search(base=rid_set_dn,
                       scope=ldb.SCOPE_SUBTREE,
                       expression="(rIDNextRID=*)",
                       attrs=['rIDAllocationPool',
                              'rIDPreviousAllocationPool',
                              'rIDNextRID'])

    # Decode the bounds of the RID allocation pools
    rid = int(res[0].get('rIDNextRID')[0])

    def split_val(num):
        high = (0xFFFFFFFF00000000 & int(num)) >> 32
        low = 0x00000000FFFFFFFF & int(num)
        return low, high
    pool_l, pool_h = split_val(res[0].get('rIDPreviousAllocationPool')[0])
    npool_l, npool_h = split_val(res[0].get('rIDAllocationPool')[0])

    # Calculate next RID based on pool bounds
    if rid == npool_h:
        raise CommandError('Out of RIDs, finished AllocPool')
    if rid == pool_h:
        if pool_h == npool_h:
            raise CommandError('Out of RIDs, finished PrevAllocPool.')
        rid = npool_l
    else:
        rid += 1

    # Construct full SID
    sid = dom_sid(samdb.get_domain_sid())
    return str(sid) + '-' + str(rid)


def get_timestamp():
    return datetime.datetime.now().isoformat().replace(':', '-')


def backup_filepath(targetdir, name, time_str):
    filename = 'samba-backup-{}-{}.tar.bz2'.format(name, time_str)
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
    match_admin = "(objectsid={}-{})".format(domainsid,
                                             security.DOMAIN_RID_ADMINISTRATOR)
    search_expr = "(&(objectClass=user){})".format(match_admin)

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
               help="Exclude secret values from the backup created")
       ]

    def run(self, sambaopts=None, credopts=None, server=None, targetdir=None,
            no_secrets=False):
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
        ctx = join_clone(logger=logger, creds=creds, lp=lp,
                         include_secrets=include_secrets, server=server,
                         dns_backend='SAMBA_INTERNAL', targetdir=tmpdir)

        # get the paths used for the clone, then drop the old samdb connection
        paths = ctx.paths
        del ctx

        # Get a free RID to use as the new DC's SID (when it gets restored)
        remote_sam = SamDB(url='ldap://' + server, credentials=creds,
                           session_info=system_session(), lp=lp)
        new_sid = get_sid_for_restore(remote_sam)
        realm = remote_sam.domain_dns_name()

        # Grab the remote DC's sysvol files and bundle them into a tar file
        sysvol_tar = os.path.join(tmpdir, 'sysvol.tar.gz')
        smb_conn = smb.SMB(server, "sysvol", lp=lp, creds=creds)
        backup_online(smb_conn, sysvol_tar, remote_sam.get_domain_sid())

        # remove the default sysvol files created by the clone (we want to
        # make sure we restore the sysvol.tar.gz files instead)
        shutil.rmtree(paths.sysvol)

        # Edit the downloaded sam.ldb to mark it as a backup
        samdb = SamDB(url=paths.samdb, session_info=system_session(), lp=lp)
        time_str = get_timestamp()
        add_backup_marker(samdb, "backupDate", time_str)
        add_backup_marker(samdb, "sidForRestore", new_sid)

        # ensure the admin user always has a password set (same as provision)
        if no_secrets:
            set_admin_password(logger, samdb)

        # Add everything in the tmpdir to the backup tar file
        backup_file = backup_filepath(targetdir, realm, time_str)
        create_log_file(tmpdir, lp, "online", server, include_secrets)
        create_backup_tar(logger, tmpdir, backup_file)

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
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def register_dns_zone(self, logger, samdb, lp, ntdsguid, host_ip,
                          host_ip6):
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
        fill_dns_data_partitions(samdb, domainsid, names.sitename, domaindn,
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

    def run(self, sambaopts=None, credopts=None, backup_file=None,
            targetdir=None, newservername=None, host_ip=None, host_ip6=None):
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
        samdb = SamDB(url=samdb_path, session_info=system_session(), lp=lp)

        # Create account using the join_add_objects function in the join object
        # We need namingContexts, account control flags, and the sid saved by
        # the backup process.
        res = samdb.search(base="", scope=ldb.SCOPE_BASE,
                           attrs=['namingContexts'])
        ncs = [str(r) for r in res[0].get('namingContexts')]

        creds = credopts.get_credentials(lp)
        ctx = DCJoinContext(logger, creds=creds, lp=lp,
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
                           attrs=['sidForRestore', 'backupRename'])
        is_rename = True if 'backupRename' in res[0] else False
        sid = res[0].get('sidForRestore')[0]
        logger.info('Creating account with SID: ' + str(sid))
        ctx.join_add_objects(specified_sid=dom_sid(sid))

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
        if is_rename:
            self.register_dns_zone(logger, samdb, lp, ctx.ntds_guid,
                                   host_ip, host_ip6)

        secrets_path = os.path.join(private_dir, 'secrets.ldb')
        secrets_ldb = Ldb(secrets_path, session_info=system_session(), lp=lp)
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
            cn = m.get('cn')[0]
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
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, "@SAMBA_DSDB")
        m["backupDate"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE,
                                             "backupDate")
        m["sidForRestore"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE,
                                                "sidForRestore")
        if is_rename:
            m["backupRename"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE,
                                                   "backupRename")
        samdb.modify(m)

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
               help="Exclude secret values from the backup created")
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
            no_secrets=False):
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
                                      server=server, targetdir=tmpdir)

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
        new_sid = get_sid_for_restore(remote_sam)

        # Grab the remote DC's sysvol files and bundle them into a tar file.
        # Note we end up with 2 sysvol dirs - the original domain's files (that
        # use the old realm) backed here, as well as default files generated
        # for the new realm as part of the clone/join.
        sysvol_tar = os.path.join(tmpdir, 'sysvol.tar.gz')
        smb_conn = smb.SMB(server, "sysvol", lp=lp, creds=creds)
        backup_online(smb_conn, sysvol_tar, remote_sam.get_domain_sid())

        # connect to the local DB (making sure we use the new/renamed config)
        lp.load(paths.smbconf)
        samdb = SamDB(url=paths.samdb, session_info=system_session(), lp=lp)

        # Edit the cloned sam.ldb to mark it as a backup
        time_str = get_timestamp()
        add_backup_marker(samdb, "backupDate", time_str)
        add_backup_marker(samdb, "sidForRestore", new_sid)
        add_backup_marker(samdb, "backupRename", old_realm)

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


class cmd_domain_backup(samba.netcmd.SuperCommand):
    '''Create or restore a backup of the domain.'''
    subcommands = {'online': cmd_domain_backup_online(),
                   'rename': cmd_domain_backup_rename(),
                   'restore': cmd_domain_backup_restore()}
