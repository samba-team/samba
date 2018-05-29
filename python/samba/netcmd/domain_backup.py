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
from samba.join import DCJoinContext, join_clone
from samba.dcerpc.security import dom_sid
from samba.netcmd import Option, CommandError
from samba.dcerpc import misc
from samba import Ldb
from fsmo import cmd_fsmo_seize
from samba.provision import make_smbconf
from samba.upgradehelpers import update_krbtgt_account_password
from samba.remove_dc import remove_dc
from samba.provision import secretsdb_self_join



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


# Add a backup-specific marker to the DB with info that we'll use during
# the restore process
def add_backup_marker(samdb, marker, value):
    m = ldb.Message()
    m.dn = ldb.Dn(samdb, "@SAMBA_DSDB")
    m[marker] = ldb.MessageElement(value, ldb.FLAG_MOD_ADD, marker)
    samdb.modify(m)


def check_online_backup_args(logger, credopts, server, targetdir):
    # Make sure we have all the required args.
    u_p = {'user': credopts.creds.get_username(),
           'pass': credopts.creds.get_password()}
    if None in u_p.values():
        raise CommandError("Creds required.")
    if server is None:
        raise CommandError('Server required')
    if targetdir is None:
        raise CommandError('Target directory required')

    if not os.path.exists(targetdir):
        logger.info('Creating targetdir %s...' % targetdir)
        os.makedirs(targetdir)


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
       ]

    def run(self, sambaopts=None, credopts=None, server=None, targetdir=None):
        logger = self.get_logger()
        logger.setLevel(logging.DEBUG)

        # Make sure we have all the required args.
        check_online_backup_args(logger, credopts, server, targetdir)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if not os.path.exists(targetdir):
            logger.info('Creating targetdir %s...' % targetdir)
            os.makedirs(targetdir)

        tmpdir = tempfile.mkdtemp(dir=targetdir)

        # Run a clone join on the remote
        ctx = join_clone(logger=logger, creds=creds, lp=lp,
                         include_secrets=True, dns_backend='SAMBA_INTERNAL',
                         server=server, targetdir=tmpdir)

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

        # Add everything in the tmpdir to the backup tar file
        backup_file = backup_filepath(targetdir, realm, time_str)
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
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self, sambaopts=None, credopts=None, backup_file=None,
            targetdir=None, newservername=None):
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
                           attrs=['sidForRestore'])
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

        # Remove DB markers added by the backup process
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, "@SAMBA_DSDB")
        m["backupDate"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE,
                                             "backupDate")
        m["sidForRestore"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE,
                                                "sidForRestore")
        samdb.modify(m)

        logger.info("Backup file successfully restored to %s" % targetdir)
        logger.info("Please check the smb.conf settings are correct before "
                    "starting samba.")


class cmd_domain_backup(samba.netcmd.SuperCommand):
    '''Create or restore a backup of the domain.'''
    subcommands = {'online': cmd_domain_backup_online(),
                   'restore': cmd_domain_backup_restore()}
