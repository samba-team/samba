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
import samba
import samba.getopt as options
from samba.samdb import SamDB
import ldb
from samba import smb
from samba.ntacls import backup_online
from samba.auth import system_session
from samba.join import DCJoinContext, join_clone
from samba.dcerpc.security import dom_sid
from samba.netcmd import Option, CommandError
import traceback

tmpdir = 'backup_temp_dir'


def rm_tmp():
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)


def using_tmp_dir(func):
    def inner(*args, **kwargs):
        try:
            rm_tmp()
            os.makedirs(tmpdir)
            rval = func(*args, **kwargs)
            rm_tmp()
            return rval
        except Exception as e:
            rm_tmp()

            # print a useful stack-trace for unexpected exceptions
            if type(e) is not CommandError:
                traceback.print_exc()
            raise e
    return inner


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

    @using_tmp_dir
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

class cmd_domain_backup(samba.netcmd.SuperCommand):
    '''Domain backup'''
    subcommands = {'online': cmd_domain_backup_online()}
