# Reads important GPO parameters and updates Samba
# Copyright (C) Luke Morrison <luc785@.hotmail.com> 2013
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


import sys
import os, shutil
import errno
import tdb
import pwd
sys.path.insert(0, "bin/python")
from samba import NTSTATUSError
from configparser import ConfigParser
from io import StringIO
import traceback
from samba.common import get_bytes
from abc import ABCMeta, abstractmethod
import xml.etree.ElementTree as etree
import re
from samba.net import Net
from samba.dcerpc import nbt
from samba.samba3 import libsmb_samba_internal as libsmb
import samba.gpo as gpo
from samba.param import LoadParm
from uuid import UUID
from tempfile import NamedTemporaryFile
from samba.dcerpc import preg
from samba.dcerpc import misc
from samba.ndr import ndr_pack, ndr_unpack
from samba.credentials import SMB_SIGNING_REQUIRED
from samba.gp.util.logging import log
from hashlib import blake2b
import numbers
from samba.common import get_string

try:
    from enum import Enum
    GPOSTATE = Enum('GPOSTATE', 'APPLY ENFORCE UNAPPLY')
except ImportError:
    class GPOSTATE:
        APPLY = 1
        ENFORCE = 2
        UNAPPLY = 3


class gp_log:
    ''' Log settings overwritten by gpo apply
    The gp_log is an xml file that stores a history of gpo changes (and the
    original setting value).

    The log is organized like so:

<gp>
    <user name="KDC-1$">
        <applylog>
            <guid count="0" value="{31B2F340-016D-11D2-945F-00C04FB984F9}" />
        </applylog>
        <guid value="{31B2F340-016D-11D2-945F-00C04FB984F9}">
            <gp_ext name="System Access">
                <attribute name="minPwdAge">-864000000000</attribute>
                <attribute name="maxPwdAge">-36288000000000</attribute>
                <attribute name="minPwdLength">7</attribute>
                <attribute name="pwdProperties">1</attribute>
            </gp_ext>
            <gp_ext name="Kerberos Policy">
                <attribute name="ticket_lifetime">1d</attribute>
                <attribute name="renew_lifetime" />
                <attribute name="clockskew">300</attribute>
            </gp_ext>
        </guid>
    </user>
</gp>

    Each guid value contains a list of extensions, which contain a list of
    attributes. The guid value represents a GPO. The attributes are the values
    of those settings prior to the application of the GPO.
    The list of guids is enclosed within a user name, which represents the user
    the settings were applied to. This user may be the samaccountname of the
    local computer, which implies that these are machine policies.
    The applylog keeps track of the order in which the GPOs were applied, so
    that they can be rolled back in reverse, returning the machine to the state
    prior to policy application.
    '''
    def __init__(self, user, gpostore, db_log=None):
        ''' Initialize the gp_log
        param user          - the username (or machine name) that policies are
                              being applied to
        param gpostore      - the GPOStorage obj which references the tdb which
                              contains gp_logs
        param db_log        - (optional) a string to initialize the gp_log
        '''
        self._state = GPOSTATE.APPLY
        self.gpostore = gpostore
        self.username = user
        if db_log:
            self.gpdb = etree.fromstring(db_log)
        else:
            self.gpdb = etree.Element('gp')
        self.user = user
        user_obj = self.gpdb.find('user[@name="%s"]' % user)
        if user_obj is None:
            user_obj = etree.SubElement(self.gpdb, 'user')
            user_obj.attrib['name'] = user

    def state(self, value):
        ''' Policy application state
        param value         - APPLY, ENFORCE, or UNAPPLY

        The behavior of the gp_log depends on whether we are applying policy,
        enforcing policy, or unapplying policy. During an apply, old settings
        are recorded in the log. During an enforce, settings are being applied
        but the gp_log does not change. During an unapply, additions to the log
        should be ignored (since function calls to apply settings are actually
        reverting policy), but removals from the log are allowed.
        '''
        # If we're enforcing, but we've unapplied, apply instead
        if value == GPOSTATE.ENFORCE:
            user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
            apply_log = user_obj.find('applylog')
            if apply_log is None or len(apply_log) == 0:
                self._state = GPOSTATE.APPLY
            else:
                self._state = value
        else:
            self._state = value

    def get_state(self):
        '''Check the GPOSTATE
        '''
        return self._state

    def set_guid(self, guid):
        ''' Log to a different GPO guid
        param guid          - guid value of the GPO from which we're applying
                              policy
        '''
        self.guid = guid
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        obj = user_obj.find('guid[@value="%s"]' % guid)
        if obj is None:
            obj = etree.SubElement(user_obj, 'guid')
            obj.attrib['value'] = guid
        if self._state == GPOSTATE.APPLY:
            apply_log = user_obj.find('applylog')
            if apply_log is None:
                apply_log = etree.SubElement(user_obj, 'applylog')
            prev = apply_log.find('guid[@value="%s"]' % guid)
            if prev is None:
                item = etree.SubElement(apply_log, 'guid')
                item.attrib['count'] = '%d' % (len(apply_log) - 1)
                item.attrib['value'] = guid

    def store(self, gp_ext_name, attribute, old_val):
        ''' Store an attribute in the gp_log
        param gp_ext_name   - Name of the extension applying policy
        param attribute     - The attribute being modified
        param old_val       - The value of the attribute prior to policy
                              application
        '''
        if self._state == GPOSTATE.UNAPPLY or self._state == GPOSTATE.ENFORCE:
            return None
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is None:
            ext = etree.SubElement(guid_obj, 'gp_ext')
            ext.attrib['name'] = gp_ext_name
        attr = ext.find('attribute[@name="%s"]' % attribute)
        if attr is None:
            attr = etree.SubElement(ext, 'attribute')
            attr.attrib['name'] = attribute
            attr.text = old_val

    def retrieve(self, gp_ext_name, attribute):
        ''' Retrieve a stored attribute from the gp_log
        param gp_ext_name   - Name of the extension which applied policy
        param attribute     - The attribute being retrieved
        return              - The value of the attribute prior to policy
                              application
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                return attr.text
        return None

    def retrieve_all(self, gp_ext_name):
        ''' Retrieve all stored attributes for this user, GPO guid, and CSE
        param gp_ext_name   - Name of the extension which applied policy
        return              - The values of the attributes prior to policy
                              application
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attrs = ext.findall('attribute')
            return {attr.attrib['name']: attr.text for attr in attrs}
        return {}

    def get_applied_guids(self):
        ''' Return a list of applied ext guids
        return              - List of guids for gpos that have applied settings
                              to the system.
        '''
        guids = []
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        if user_obj is not None:
            apply_log = user_obj.find('applylog')
            if apply_log is not None:
                guid_objs = apply_log.findall('guid[@count]')
                guids_by_count = [(g.get('count'), g.get('value'))
                                  for g in guid_objs]
                guids_by_count.sort(reverse=True)
                guids.extend(guid for count, guid in guids_by_count)
        return guids

    def get_applied_settings(self, guids):
        ''' Return a list of applied ext guids
        return              - List of tuples containing the guid of a gpo, then
                              a dictionary of policies and their values prior
                              policy application. These are sorted so that the
                              most recently applied settings are removed first.
        '''
        ret = []
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        for guid in guids:
            guid_settings = user_obj.find('guid[@value="%s"]' % guid)
            exts = guid_settings.findall('gp_ext')
            settings = {}
            for ext in exts:
                attr_dict = {}
                attrs = ext.findall('attribute')
                for attr in attrs:
                    attr_dict[attr.attrib['name']] = attr.text
                settings[ext.attrib['name']] = attr_dict
            ret.append((guid, settings))
        return ret

    def delete(self, gp_ext_name, attribute):
        ''' Remove an attribute from the gp_log
        param gp_ext_name   - name of extension from which to remove the
                              attribute
        param attribute     - attribute to remove
        '''
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attr = ext.find('attribute[@name="%s"]' % attribute)
            if attr is not None:
                ext.remove(attr)
                if len(ext) == 0:
                    guid_obj.remove(ext)

    def commit(self):
        ''' Write gp_log changes to disk '''
        self.gpostore.store(self.username, etree.tostring(self.gpdb, 'utf-8'))


class GPOStorage:
    def __init__(self, log_file):
        if os.path.isfile(log_file):
            self.log = tdb.open(log_file)
        else:
            self.log = tdb.Tdb(log_file, 0, tdb.DEFAULT, os.O_CREAT | os.O_RDWR)

    def start(self):
        self.log.transaction_start()

    def get_int(self, key):
        try:
            return int(self.log.get(get_bytes(key)))
        except TypeError:
            return None

    def get(self, key):
        return self.log.get(get_bytes(key))

    def get_gplog(self, user):
        return gp_log(user, self, self.log.get(get_bytes(user)))

    def store(self, key, val):
        self.log.store(get_bytes(key), get_bytes(val))

    def cancel(self):
        self.log.transaction_cancel()

    def delete(self, key):
        self.log.delete(get_bytes(key))

    def commit(self):
        self.log.transaction_commit()

    def __del__(self):
        self.log.close()


class gp_ext(object):
    __metaclass__ = ABCMeta

    def __init__(self, lp, creds, username, store):
        self.lp = lp
        self.creds = creds
        self.username = username
        self.gp_db = store.get_gplog(username)

    @abstractmethod
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        pass

    @abstractmethod
    def read(self, policy):
        pass

    def parse(self, afile):
        local_path = self.lp.cache_path('gpo_cache')
        data_file = os.path.join(local_path, check_safe_path(afile).upper())
        if os.path.exists(data_file):
            return self.read(data_file)
        return None

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def rsop(self, gpo):
        return {}


class gp_inf_ext(gp_ext):
    def read(self, data_file):
        policy = open(data_file, 'rb').read()
        inf_conf = ConfigParser(interpolation=None)
        inf_conf.optionxform = str
        try:
            inf_conf.readfp(StringIO(policy.decode()))
        except UnicodeDecodeError:
            inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf


class gp_pol_ext(gp_ext):
    def read(self, data_file):
        raw = open(data_file, 'rb').read()
        return ndr_unpack(preg.file, raw)


class gp_xml_ext(gp_ext):
    def read(self, data_file):
        raw = open(data_file, 'rb').read()
        try:
            return etree.fromstring(raw.decode())
        except UnicodeDecodeError:
            return etree.fromstring(raw.decode('utf-16'))


class gp_applier(object):
    '''Group Policy Applier/Unapplier/Modifier
    The applier defines functions for monitoring policy application,
    removal, and modification. It must be a multi-derived class paired
    with a subclass of gp_ext.
    '''
    __metaclass__ = ABCMeta

    def cache_add_attribute(self, guid, attribute, value):
        '''Add an attribute and value to the Group Policy cache
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy being applied
        value       - The value of the policy being applied

        Normally called by the subclass apply() function after applying policy.
        '''
        self.gp_db.set_guid(guid)
        self.gp_db.store(str(self), attribute, value)
        self.gp_db.commit()

    def cache_remove_attribute(self, guid, attribute):
        '''Remove an attribute from the Group Policy cache
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy being unapplied

        Normally called by the subclass unapply() function when removing old
        policy.
        '''
        self.gp_db.set_guid(guid)
        self.gp_db.delete(str(self), attribute)
        self.gp_db.commit()

    def cache_get_attribute_value(self, guid, attribute):
        '''Retrieve the value stored in the cache for the given attribute
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy
        '''
        self.gp_db.set_guid(guid)
        return self.gp_db.retrieve(str(self), attribute)

    def cache_get_all_attribute_values(self, guid):
        '''Retrieve all attribute/values currently stored for this gpo+policy
        guid        - The GPO guid which applies this policy
        '''
        self.gp_db.set_guid(guid)
        return self.gp_db.retrieve_all(str(self))

    def cache_get_apply_state(self):
        '''Return the current apply state
        return      - APPLY|ENFORCE|UNAPPLY
        '''
        return self.gp_db.get_state()

    def generate_attribute(self, name, *args):
        '''Generate an attribute name from arbitrary data
        name            - A name to ensure uniqueness
        args            - Any arbitrary set of args, str or bytes
        return          - A blake2b digest of the data, the attribute

        The importance here is the digest of the data makes the attribute
        reproducible and uniquely identifies it. Hashing the name with
        the data ensures we don't falsly identify a match which is the same
        text in a different file. Using this attribute generator is optional.
        '''
        data = b''.join([get_bytes(arg) for arg in [*args]])
        return blake2b(get_bytes(name)+data).hexdigest()

    def generate_value_hash(self, *args):
        '''Generate a unique value which identifies value changes
        args            - Any arbitrary set of args, str or bytes
        return          - A blake2b digest of the data, the value represented
        '''
        data = b''.join([get_bytes(arg) for arg in [*args]])
        return blake2b(data).hexdigest()

    @abstractmethod
    def unapply(self, guid, attribute, value):
        '''Group Policy Unapply
        guid            - The GPO guid which applies this policy
        attribute       - The attribute name of the policy being unapplied
        value           - The value of the policy being unapplied
        '''
        pass

    @abstractmethod
    def apply(self, guid, attribute, applier_func, *args):
        '''Group Policy Apply
        guid            - The GPO guid which applies this policy
        attribute       - The attribute name of the policy being applied
        applier_func    - An applier function which takes variable args
        args            - The variable arguments to pass to applier_func

        The applier_func function MUST return the value of the policy being
        applied. It's important that implementations of `apply` check for and
        first unapply any changed policy. See for example calls to
        `cache_get_all_attribute_values()` which searches for all policies
        applied by this GPO for this Client Side Extension (CSE).
        '''
        pass

    def clean(self, guid, keep=[], remove=[], **kwargs):
        '''Cleanup old removed attributes
        keep    - A list of attributes to keep
        remove  - A single attribute to remove, or a list of attributes to
                  remove
        kwargs  - Additional keyword args required by the subclass unapply
                  function

        This is only necessary for CSEs which provide multiple attributes.
        '''
        # Clean syntax is, either provide a single remove attribute,
        # or a list of either removal attributes or keep attributes.
        if type(remove) != list:
            value = self.cache_get_attribute_value(guid, remove)
            if value is not None:
                self.unapply(guid, remove, value, **kwargs)
        else:
            old_vals = self.cache_get_all_attribute_values(guid)
            for attribute, value in old_vals.items():
                if (len(remove) > 0 and attribute in remove) or \
                   (len(keep) > 0 and attribute not in keep):
                    self.unapply(guid, attribute, value, **kwargs)


class gp_file_applier(gp_applier):
    '''Group Policy File Applier/Unapplier/Modifier
    Subclass of abstract class gp_applier for monitoring policy applied
    via a file.
    '''

    def __generate_value(self, value_hash, files, sep):
        data = [value_hash]
        data.extend(files)
        return sep.join(data)

    def __parse_value(self, value, sep):
        '''Parse a value
        return          - A unique HASH, followed by the file list
        '''
        if value is None:
            return None, []
        data = value.split(sep)
        if '/' in data[0]:
            # The first element is not a hash, but a filename. This is a
            # legacy value.
            return None, data
        else:
            return data[0], data[1:] if len(data) > 1 else []

    def unapply(self, guid, attribute, files, sep=':'):
        # If the value isn't a list of files, parse value from the log
        if type(files) != list:
            _, files = self.__parse_value(files, sep)
        for file in files:
            if os.path.exists(file):
                os.unlink(file)
        self.cache_remove_attribute(guid, attribute)

    def apply(self, guid, attribute, value_hash, applier_func, *args, sep=':'):
        '''
        applier_func MUST return a list of files created by the applier.

        This applier is for policies which only apply to a single file (with
        a couple small exceptions). This applier will remove any policy applied
        by this GPO which doesn't match the new policy.
        '''
        # If the policy has changed, unapply, then apply new policy
        old_val = self.cache_get_attribute_value(guid, attribute)
        # Ignore removal if this policy is applied and hasn't changed
        old_val_hash, old_val_files = self.__parse_value(old_val, sep)
        if (old_val_hash != value_hash or \
                self.cache_get_apply_state() == GPOSTATE.ENFORCE) or \
                not all([os.path.exists(f) for f in old_val_files]):
            self.unapply(guid, attribute, old_val_files)
        else:
            # If policy is already applied, skip application
            return

        # Apply the policy and log the changes
        files = applier_func(*args)
        new_value = self.__generate_value(value_hash, files, sep)
        self.cache_add_attribute(guid, attribute, new_value)


''' Fetch the hostname of a writable DC '''


def get_dc_hostname(creds, lp):
    net = Net(creds=creds, lp=lp)
    cldap_ret = net.finddc(domain=lp.get('realm'), flags=(nbt.NBT_SERVER_LDAP |
                                                          nbt.NBT_SERVER_DS))
    return cldap_ret.pdc_dns_name


''' Fetch a list of GUIDs for applicable GPOs '''


def get_gpo_list(dc_hostname, creds, lp, username):
    gpos = []
    ads = gpo.ADS_STRUCT(dc_hostname, lp, creds)
    if ads.connect():
        # username is DOM\\SAM, but get_gpo_list expects SAM
        gpos = ads.get_gpo_list(username.split('\\')[-1])
    return gpos


def cache_gpo_dir(conn, cache, sub_dir):
    loc_sub_dir = sub_dir.upper()
    local_dir = os.path.join(cache, loc_sub_dir)
    try:
        os.makedirs(local_dir, mode=0o755)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    for fdata in conn.list(sub_dir):
        if fdata['attrib'] & libsmb.FILE_ATTRIBUTE_DIRECTORY:
            cache_gpo_dir(conn, cache, os.path.join(sub_dir, fdata['name']))
        else:
            local_name = fdata['name'].upper()
            f = NamedTemporaryFile(delete=False, dir=local_dir)
            fname = os.path.join(sub_dir, fdata['name']).replace('/', '\\')
            f.write(conn.loadfile(fname))
            f.close()
            os.rename(f.name, os.path.join(local_dir, local_name))


def check_safe_path(path):
    dirs = re.split('/|\\\\', path)
    if 'sysvol' in path.lower():
        ldirs = re.split('/|\\\\', path.lower())
        dirs = dirs[ldirs.index('sysvol') + 1:]
    if '..' not in dirs:
        return os.path.join(*dirs)
    raise OSError(path)


def check_refresh_gpo_list(dc_hostname, lp, creds, gpos):
    # Force signing for the connection
    saved_signing_state = creds.get_smb_signing()
    creds.set_smb_signing(SMB_SIGNING_REQUIRED)
    conn = libsmb.Conn(dc_hostname, 'sysvol', lp=lp, creds=creds)
    # Reset signing state
    creds.set_smb_signing(saved_signing_state)
    cache_path = lp.cache_path('gpo_cache')
    for gpo in gpos:
        if not gpo.file_sys_path:
            continue
        cache_gpo_dir(conn, cache_path, check_safe_path(gpo.file_sys_path))


def get_deleted_gpos_list(gp_db, gpos):
    applied_gpos = gp_db.get_applied_guids()
    current_guids = set([p.name for p in gpos])
    deleted_gpos = [guid for guid in applied_gpos if guid not in current_guids]
    return gp_db.get_applied_settings(deleted_gpos)

def gpo_version(lp, path):
    # gpo.gpo_get_sysvol_gpt_version() reads the GPT.INI from a local file,
    # read from the gpo client cache.
    gpt_path = lp.cache_path(os.path.join('gpo_cache', path))
    return int(gpo.gpo_get_sysvol_gpt_version(gpt_path)[1])


def apply_gp(lp, creds, store, gp_extensions, username, target, force=False):
    gp_db = store.get_gplog(username)
    dc_hostname = get_dc_hostname(creds, lp)
    gpos = get_gpo_list(dc_hostname, creds, lp, username)
    del_gpos = get_deleted_gpos_list(gp_db, gpos)
    try:
        check_refresh_gpo_list(dc_hostname, lp, creds, gpos)
    except:
        log.error('Failed downloading gpt cache from \'%s\' using SMB'
                  % dc_hostname)
        return

    if force:
        changed_gpos = gpos
        gp_db.state(GPOSTATE.ENFORCE)
    else:
        changed_gpos = []
        for gpo_obj in gpos:
            if not gpo_obj.file_sys_path:
                continue
            guid = gpo_obj.name
            path = check_safe_path(gpo_obj.file_sys_path).upper()
            version = gpo_version(lp, path)
            if version != store.get_int(guid):
                log.info('GPO %s has changed' % guid)
                changed_gpos.append(gpo_obj)
        gp_db.state(GPOSTATE.APPLY)

    store.start()
    for ext in gp_extensions:
        try:
            ext = ext(lp, creds, username, store)
            if target == 'Computer':
                ext.process_group_policy(del_gpos, changed_gpos)
            else:
                drop_privileges(creds.get_principal(), ext.process_group_policy,
                                del_gpos, changed_gpos)
        except Exception as e:
            log.error('Failed to apply extension  %s' % str(ext))
            log.error('Message was: %s: %s' % (type(e).__name__, str(e)))
            log.debug(traceback.format_exc())
            continue
    for gpo_obj in gpos:
        if not gpo_obj.file_sys_path:
            continue
        guid = gpo_obj.name
        path = check_safe_path(gpo_obj.file_sys_path).upper()
        version = gpo_version(lp, path)
        store.store(guid, '%i' % version)
    store.commit()


def unapply_gp(lp, creds, store, gp_extensions, username, target):
    gp_db = store.get_gplog(username)
    gp_db.state(GPOSTATE.UNAPPLY)
    # Treat all applied gpos as deleted
    del_gpos = gp_db.get_applied_settings(gp_db.get_applied_guids())
    store.start()
    for ext in gp_extensions:
        try:
            ext = ext(lp, creds, username, store)
            if target == 'Computer':
                ext.process_group_policy(del_gpos, [])
            else:
                drop_privileges(username, ext.process_group_policy,
                                del_gpos, [])
        except Exception as e:
            log.error('Failed to unapply extension  %s' % str(ext))
            log.error('Message was: ' + str(e))
            continue
    store.commit()


def __rsop_vals(vals, level=4):
    if type(vals) == dict:
        ret = [' '*level + '[ %s ] = %s' % (k, __rsop_vals(v, level+2))
                for k, v in vals.items()]
        return '\n' + '\n'.join(ret)
    elif type(vals) == list:
        ret = [' '*level + '[ %s ]' % __rsop_vals(v, level+2) for v in vals]
        return '\n' + '\n'.join(ret)
    else:
        if isinstance(vals, numbers.Number):
            return ' '*(level+2) + str(vals)
        else:
            return ' '*(level+2) + get_string(vals)

def rsop(lp, creds, store, gp_extensions, username, target):
    dc_hostname = get_dc_hostname(creds, lp)
    gpos = get_gpo_list(dc_hostname, creds, lp, username)
    check_refresh_gpo_list(dc_hostname, lp, creds, gpos)

    print('Resultant Set of Policy')
    print('%s Policy\n' % target)
    term_width = shutil.get_terminal_size(fallback=(120, 50))[0]
    for gpo in gpos:
        if gpo.display_name.strip() == 'Local Policy':
            continue # We never apply local policy
        print('GPO: %s' % gpo.display_name)
        print('='*term_width)
        for ext in gp_extensions:
            ext = ext(lp, creds, username, store)
            cse_name_m = re.findall("'([\w\.]+)'", str(type(ext)))
            if len(cse_name_m) > 0:
                cse_name = cse_name_m[-1].split('.')[-1]
            else:
                cse_name = ext.__module__.split('.')[-1]
            print('  CSE: %s' % cse_name)
            print('  ' + ('-'*int(term_width/2)))
            for section, settings in ext.rsop(gpo).items():
                print('    Policy Type: %s' % section)
                print('    ' + ('-'*int(term_width/2)))
                print(__rsop_vals(settings).lstrip('\n'))
                print('    ' + ('-'*int(term_width/2)))
            print('  ' + ('-'*int(term_width/2)))
        print('%s\n' % ('='*term_width))


def parse_gpext_conf(smb_conf):
    from samba.samba3 import param as s3param
    lp = s3param.get_context()
    if smb_conf is not None:
        lp.load(smb_conf)
    else:
        lp.load_default()
    ext_conf = lp.state_path('gpext.conf')
    parser = ConfigParser(interpolation=None)
    parser.read(ext_conf)
    return lp, parser


def atomic_write_conf(lp, parser):
    ext_conf = lp.state_path('gpext.conf')
    with NamedTemporaryFile(mode="w+", delete=False, dir=os.path.dirname(ext_conf)) as f:
        parser.write(f)
        os.rename(f.name, ext_conf)


def check_guid(guid):
    # Check for valid guid with curly braces
    if guid[0] != '{' or guid[-1] != '}' or len(guid) != 38:
        return False
    try:
        UUID(guid, version=4)
    except ValueError:
        return False
    return True


def register_gp_extension(guid, name, path,
                          smb_conf=None, machine=True, user=True):
    # Check that the module exists
    if not os.path.exists(path):
        return False
    if not check_guid(guid):
        return False

    lp, parser = parse_gpext_conf(smb_conf)
    if guid not in parser.sections():
        parser.add_section(guid)
    parser.set(guid, 'DllName', path)
    parser.set(guid, 'ProcessGroupPolicy', name)
    parser.set(guid, 'NoMachinePolicy', "0" if machine else "1")
    parser.set(guid, 'NoUserPolicy', "0" if user else "1")

    atomic_write_conf(lp, parser)

    return True


def list_gp_extensions(smb_conf=None):
    _, parser = parse_gpext_conf(smb_conf)
    results = {}
    for guid in parser.sections():
        results[guid] = {}
        results[guid]['DllName'] = parser.get(guid, 'DllName')
        results[guid]['ProcessGroupPolicy'] = \
            parser.get(guid, 'ProcessGroupPolicy')
        results[guid]['MachinePolicy'] = \
            not int(parser.get(guid, 'NoMachinePolicy'))
        results[guid]['UserPolicy'] = not int(parser.get(guid, 'NoUserPolicy'))
    return results


def unregister_gp_extension(guid, smb_conf=None):
    if not check_guid(guid):
        return False

    lp, parser = parse_gpext_conf(smb_conf)
    if guid in parser.sections():
        parser.remove_section(guid)

    atomic_write_conf(lp, parser)

    return True


def set_privileges(username, uid, gid):
    '''
    Set current process privileges
    '''

    os.setegid(gid)
    os.seteuid(uid)


def drop_privileges(username, func, *args):
    '''
    Run supplied function with privileges for specified username.
    '''
    current_uid = os.getuid()

    if not current_uid == 0:
        raise Exception('Not enough permissions to drop privileges')

    user_uid = pwd.getpwnam(username).pw_uid
    user_gid = pwd.getpwnam(username).pw_gid

    # Drop privileges
    set_privileges(username, user_uid, user_gid)

    # We need to catch exception in order to be able to restore
    # privileges later in this function
    out = None
    exc = None
    try:
        out = func(*args)
    except Exception as e:
        exc = e

    # Restore privileges
    set_privileges('root', current_uid, 0)

    if exc:
        raise exc

    return out
