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
from samba import WERRORError
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
from uuid import UUID
from tempfile import NamedTemporaryFile
from samba.dcerpc import preg
from samba.ndr import ndr_unpack
from samba.credentials import SMB_SIGNING_REQUIRED
from samba.gp.util.logging import log
from hashlib import blake2b
import numbers
from samba.common import get_string
from samba.samdb import SamDB
from samba.auth import system_session
import ldb
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT, GPLINK_OPT_ENFORCE, GPLINK_OPT_DISABLE, GPO_BLOCK_INHERITANCE
from samba.auth import AUTH_SESSION_INFO_DEFAULT_GROUPS, AUTH_SESSION_INFO_AUTHENTICATED, AUTH_SESSION_INFO_SIMPLE_PRIVILEGES
from samba.dcerpc import security
import samba.security
from samba.dcerpc import nbt
from datetime import datetime


try:
    from enum import Enum
    GPOSTATE = Enum('GPOSTATE', 'APPLY ENFORCE UNAPPLY')
except ImportError:
    class GPOSTATE:
        APPLY = 1
        ENFORCE = 2
        UNAPPLY = 3


class gp_log:
    """ Log settings overwritten by gpo apply
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
    """
    def __init__(self, user, gpostore, db_log=None):
        """ Initialize the gp_log
        param user          - the username (or machine name) that policies are
                              being applied to
        param gpostore      - the GPOStorage obj which references the tdb which
                              contains gp_logs
        param db_log        - (optional) a string to initialize the gp_log
        """
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
        """ Policy application state
        param value         - APPLY, ENFORCE, or UNAPPLY

        The behavior of the gp_log depends on whether we are applying policy,
        enforcing policy, or unapplying policy. During an apply, old settings
        are recorded in the log. During an enforce, settings are being applied
        but the gp_log does not change. During an unapply, additions to the log
        should be ignored (since function calls to apply settings are actually
        reverting policy), but removals from the log are allowed.
        """
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
        """Check the GPOSTATE
        """
        return self._state

    def set_guid(self, guid):
        """ Log to a different GPO guid
        param guid          - guid value of the GPO from which we're applying
                              policy
        """
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
        """ Store an attribute in the gp_log
        param gp_ext_name   - Name of the extension applying policy
        param attribute     - The attribute being modified
        param old_val       - The value of the attribute prior to policy
                              application
        """
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
        """ Retrieve a stored attribute from the gp_log
        param gp_ext_name   - Name of the extension which applied policy
        param attribute     - The attribute being retrieved
        return              - The value of the attribute prior to policy
                              application
        """
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
        """ Retrieve all stored attributes for this user, GPO guid, and CSE
        param gp_ext_name   - Name of the extension which applied policy
        return              - The values of the attributes prior to policy
                              application
        """
        user_obj = self.gpdb.find('user[@name="%s"]' % self.user)
        guid_obj = user_obj.find('guid[@value="%s"]' % self.guid)
        assert guid_obj is not None, "gpo guid was not set"
        ext = guid_obj.find('gp_ext[@name="%s"]' % gp_ext_name)
        if ext is not None:
            attrs = ext.findall('attribute')
            return {attr.attrib['name']: attr.text for attr in attrs}
        return {}

    def get_applied_guids(self):
        """ Return a list of applied ext guids
        return              - List of guids for gpos that have applied settings
                              to the system.
        """
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
        """ Return a list of applied ext guids
        return              - List of tuples containing the guid of a gpo, then
                              a dictionary of policies and their values prior
                              policy application. These are sorted so that the
                              most recently applied settings are removed first.
        """
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
        """ Remove an attribute from the gp_log
        param gp_ext_name   - name of extension from which to remove the
                              attribute
        param attribute     - attribute to remove
        """
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
        """ Write gp_log changes to disk """
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
        with open(data_file, 'rb') as f:
            policy = f.read()
        inf_conf = ConfigParser(interpolation=None)
        inf_conf.optionxform = str
        try:
            inf_conf.read_file(StringIO(policy.decode()))
        except UnicodeDecodeError:
            inf_conf.read_file(StringIO(policy.decode('utf-16')))
        return inf_conf


class gp_pol_ext(gp_ext):
    def read(self, data_file):
        with open(data_file, 'rb') as f:
            raw = f.read()
        return ndr_unpack(preg.file, raw)


class gp_xml_ext(gp_ext):
    def read(self, data_file):
        with open(data_file, 'rb') as f:
            raw = f.read()
        try:
            return etree.fromstring(raw.decode())
        except UnicodeDecodeError:
            return etree.fromstring(raw.decode('utf-16'))


class gp_applier(object):
    """Group Policy Applier/Unapplier/Modifier
    The applier defines functions for monitoring policy application,
    removal, and modification. It must be a multi-derived class paired
    with a subclass of gp_ext.
    """
    __metaclass__ = ABCMeta

    def cache_add_attribute(self, guid, attribute, value):
        """Add an attribute and value to the Group Policy cache
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy being applied
        value       - The value of the policy being applied

        Normally called by the subclass apply() function after applying policy.
        """
        self.gp_db.set_guid(guid)
        self.gp_db.store(str(self), attribute, value)
        self.gp_db.commit()

    def cache_remove_attribute(self, guid, attribute):
        """Remove an attribute from the Group Policy cache
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy being unapplied

        Normally called by the subclass unapply() function when removing old
        policy.
        """
        self.gp_db.set_guid(guid)
        self.gp_db.delete(str(self), attribute)
        self.gp_db.commit()

    def cache_get_attribute_value(self, guid, attribute):
        """Retrieve the value stored in the cache for the given attribute
        guid        - The GPO guid which applies this policy
        attribute   - The attribute name of the policy
        """
        self.gp_db.set_guid(guid)
        return self.gp_db.retrieve(str(self), attribute)

    def cache_get_all_attribute_values(self, guid):
        """Retrieve all attribute/values currently stored for this gpo+policy
        guid        - The GPO guid which applies this policy
        """
        self.gp_db.set_guid(guid)
        return self.gp_db.retrieve_all(str(self))

    def cache_get_apply_state(self):
        """Return the current apply state
        return      - APPLY|ENFORCE|UNAPPLY
        """
        return self.gp_db.get_state()

    def generate_attribute(self, name, *args):
        """Generate an attribute name from arbitrary data
        name            - A name to ensure uniqueness
        args            - Any arbitrary set of args, str or bytes
        return          - A blake2b digest of the data, the attribute

        The importance here is the digest of the data makes the attribute
        reproducible and uniquely identifies it. Hashing the name with
        the data ensures we don't falsely identify a match which is the same
        text in a different file. Using this attribute generator is optional.
        """
        data = b''.join([get_bytes(arg) for arg in [*args]])
        return blake2b(get_bytes(name)+data).hexdigest()

    def generate_value_hash(self, *args):
        """Generate a unique value which identifies value changes
        args            - Any arbitrary set of args, str or bytes
        return          - A blake2b digest of the data, the value represented
        """
        data = b''.join([get_bytes(arg) for arg in [*args]])
        return blake2b(data).hexdigest()

    @abstractmethod
    def unapply(self, guid, attribute, value):
        """Group Policy Unapply
        guid            - The GPO guid which applies this policy
        attribute       - The attribute name of the policy being unapplied
        value           - The value of the policy being unapplied
        """
        pass

    @abstractmethod
    def apply(self, guid, attribute, applier_func, *args):
        """Group Policy Apply
        guid            - The GPO guid which applies this policy
        attribute       - The attribute name of the policy being applied
        applier_func    - An applier function which takes variable args
        args            - The variable arguments to pass to applier_func

        The applier_func function MUST return the value of the policy being
        applied. It's important that implementations of `apply` check for and
        first unapply any changed policy. See for example calls to
        `cache_get_all_attribute_values()` which searches for all policies
        applied by this GPO for this Client Side Extension (CSE).
        """
        pass

    def clean(self, guid, keep=None, remove=None, **kwargs):
        """Cleanup old removed attributes
        keep    - A list of attributes to keep
        remove  - A single attribute to remove, or a list of attributes to
                  remove
        kwargs  - Additional keyword args required by the subclass unapply
                  function

        This is only necessary for CSEs which provide multiple attributes.
        """
        # Clean syntax is, either provide a single remove attribute,
        # or a list of either removal attributes or keep attributes.
        if keep is None:
            keep = []
        if remove is None:
            remove = []

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


class gp_misc_applier(gp_applier):
    """Group Policy Miscellaneous Applier/Unapplier/Modifier
    """

    def generate_value(self, **kwargs):
        data = etree.Element('data')
        for k, v in kwargs.items():
            arg = etree.SubElement(data, k)
            arg.text = get_string(v)
        return get_string(etree.tostring(data, 'utf-8'))

    def parse_value(self, value):
        vals = {}
        try:
            data = etree.fromstring(value)
        except etree.ParseError:
            # If parsing fails, then it's an old cache value
            return {'old_val': value}
        except TypeError:
            return {}
        itr = data.iter()
        next(itr) # Skip the top element
        for item in itr:
            vals[item.tag] = item.text
        return vals


class gp_file_applier(gp_applier):
    """Group Policy File Applier/Unapplier/Modifier
    Subclass of abstract class gp_applier for monitoring policy applied
    via a file.
    """

    def __generate_value(self, value_hash, files, sep):
        data = [value_hash]
        data.extend(files)
        return sep.join(data)

    def __parse_value(self, value, sep):
        """Parse a value
        return          - A unique HASH, followed by the file list
        """
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
        """
        applier_func MUST return a list of files created by the applier.

        This applier is for policies which only apply to a single file (with
        a couple small exceptions). This applier will remove any policy applied
        by this GPO which doesn't match the new policy.
        """
        # If the policy has changed, unapply, then apply new policy
        old_val = self.cache_get_attribute_value(guid, attribute)
        # Ignore removal if this policy is applied and hasn't changed
        old_val_hash, old_val_files = self.__parse_value(old_val, sep)
        if (old_val_hash != value_hash or
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


""" Fetch the hostname of a writable DC """


def get_dc_hostname(creds, lp):
    net = Net(creds=creds, lp=lp)
    cldap_ret = net.finddc(domain=lp.get('realm'), flags=(nbt.NBT_SERVER_LDAP |
                                                          nbt.NBT_SERVER_DS))
    return cldap_ret.pdc_dns_name


""" Fetch a list of GUIDs for applicable GPOs """


def get_gpo(samdb, gpo_dn):
    g = gpo.GROUP_POLICY_OBJECT()
    attrs = [
        "cn",
        "displayName",
        "flags",
        "gPCFileSysPath",
        "gPCFunctionalityVersion",
        "gPCMachineExtensionNames",
        "gPCUserExtensionNames",
        "gPCWQLFilter",
        "name",
        "nTSecurityDescriptor",
        "versionNumber"
    ]
    if gpo_dn.startswith("LDAP://"):
        gpo_dn = gpo_dn.lstrip("LDAP://")

    sd_flags = (security.SECINFO_OWNER |
                security.SECINFO_GROUP |
                security.SECINFO_DACL)
    try:
        res = samdb.search(gpo_dn, ldb.SCOPE_BASE, "(objectclass=*)", attrs,
                           controls=['sd_flags:1:%d' % sd_flags])
    except Exception:
        log.error('Failed to fetch gpo object with nTSecurityDescriptor')
        raise
    if res.count != 1:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT,
                           'get_gpo: search failed')

    g.ds_path = gpo_dn
    if 'versionNumber' in res.msgs[0].keys():
        g.version = int(res.msgs[0]['versionNumber'][0])
    if 'flags' in res.msgs[0].keys():
        g.options = int(res.msgs[0]['flags'][0])
    if 'gPCFileSysPath' in res.msgs[0].keys():
        g.file_sys_path = res.msgs[0]['gPCFileSysPath'][0].decode()
    if 'displayName' in res.msgs[0].keys():
        g.display_name = res.msgs[0]['displayName'][0].decode()
    if 'name' in res.msgs[0].keys():
        g.name = res.msgs[0]['name'][0].decode()
    if 'gPCMachineExtensionNames' in res.msgs[0].keys():
        g.machine_extensions = str(res.msgs[0]['gPCMachineExtensionNames'][0])
    if 'gPCUserExtensionNames' in res.msgs[0].keys():
        g.user_extensions = str(res.msgs[0]['gPCUserExtensionNames'][0])
    if 'nTSecurityDescriptor' in res.msgs[0].keys():
        g.set_sec_desc(bytes(res.msgs[0]['nTSecurityDescriptor'][0]))
    return g

class GP_LINK:
    def __init__(self, gPLink, gPOptions):
        self.link_names = []
        self.link_opts = []
        self.gpo_parse_gplink(gPLink)
        self.gp_opts = int(gPOptions)

    def gpo_parse_gplink(self, gPLink):
        # normally formed link looks like [LDAP://host/path;options]
        # empty link looks like [ ]
        for p in gPLink.decode().split(']'):
            if not p or ';' not in p:
                continue
            log.debug('gpo_parse_gplink: processing link')
            p = p.lstrip('[')
            link_name, link_opt = p.split(';')
            log.debug('gpo_parse_gplink: link: {}'.format(link_name))
            log.debug('gpo_parse_gplink: opt: {}'.format(link_opt))
            self.link_names.append(link_name)
            self.link_opts.append(int(link_opt))

    def num_links(self):
        if len(self.link_names) != len(self.link_opts):
            raise RuntimeError('Link names and opts mismatch')
        return len(self.link_names)

def find_samaccount(samdb, samaccountname):
    attrs = ['dn', 'userAccountControl']
    res = samdb.search(samdb.get_default_basedn(), ldb.SCOPE_SUBTREE,
                       '(sAMAccountName={})'.format(samaccountname), attrs)
    if res.count != 1:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT,
            "Failed to find samAccountName '{}'".format(samaccountname)
        )
    uac = int(res.msgs[0]['userAccountControl'][0])
    dn = res.msgs[0]['dn']
    log.info('Found dn {} for samaccountname {}'.format(dn, samaccountname))
    return uac, dn

def get_gpo_link(samdb, link_dn):
    res = samdb.search(link_dn, ldb.SCOPE_BASE,
                       '(objectclass=*)', ['gPLink', 'gPOptions'])
    if res.count != 1:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, 'get_gpo_link: no result')
    if 'gPLink' not in res.msgs[0]:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_ATTRIBUTE,
            "get_gpo_link: no 'gPLink' attribute found for '{}'".format(link_dn)
        )
    gPLink = res.msgs[0]['gPLink'][0]
    gPOptions = 0
    if 'gPOptions' in res.msgs[0]:
        gPOptions = res.msgs[0]['gPOptions'][0]
    else:
        log.debug("get_gpo_link: no 'gPOptions' attribute found")
    return GP_LINK(gPLink, gPOptions)

def add_gplink_to_gpo_list(samdb, gpo_list, forced_gpo_list, link_dn, gp_link,
                           link_type, only_add_forced_gpos, token):
    for i in range(gp_link.num_links()-1, -1, -1):
        is_forced = (gp_link.link_opts[i] & GPLINK_OPT_ENFORCE) != 0
        if gp_link.link_opts[i] & GPLINK_OPT_DISABLE:
            log.debug('skipping disabled GPO')
            continue

        if only_add_forced_gpos:
            if not is_forced:
                log.debug("skipping nonenforced GPO link "
                          "because GPOPTIONS_BLOCK_INHERITANCE "
                          "has been set")
                continue
            else:
                log.debug("adding enforced GPO link although "
                          "the GPOPTIONS_BLOCK_INHERITANCE "
                          "has been set")

        try:
            new_gpo = get_gpo(samdb, gp_link.link_names[i])
        except ldb.LdbError as e:
            (enum, estr) = e.args
            log.debug("failed to get gpo: %s" % gp_link.link_names[i])
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                log.debug("skipping empty gpo: %s" % gp_link.link_names[i])
                continue
            return
        else:
            try:
                sec_desc = ndr_unpack(security.descriptor,
                                      new_gpo.get_sec_desc_buf())
                samba.security.access_check(sec_desc, token,
                                            security.SEC_STD_READ_CONTROL |
                                            security.SEC_ADS_LIST |
                                            security.SEC_ADS_READ_PROP)
            except Exception as e:
                log.debug("skipping GPO \"%s\" as object "
                          "has no access to it" % new_gpo.display_name)
                continue

            new_gpo.link = str(link_dn)
            new_gpo.link_type = link_type

            if is_forced:
                forced_gpo_list.insert(0, new_gpo)
            else:
                gpo_list.insert(0, new_gpo)

            log.debug("add_gplink_to_gpo_list: added GPLINK #%d %s "
                      "to GPO list" % (i, gp_link.link_names[i]))

def merge_with_system_token(token_1):
    sids = token_1.sids
    system_token = system_session().security_token
    sids.extend(system_token.sids)
    token_1.sids = sids
    token_1.rights_mask |= system_token.rights_mask
    token_1.privilege_mask |= system_token.privilege_mask
    # There are no claims in the system token, so it is safe not to merge the claims
    return token_1


def site_dn_for_machine(samdb, dc_hostname, lp, creds, hostname):
    # [MS-GPOL] 3.2.5.1.4 Site Search

    # The netr_DsRGetSiteName() needs to run over local rpc, however we do not
    # have the call implemented in our rpc_server.
    # What netr_DsRGetSiteName() actually does is an ldap query to get
    # the sitename, we can do the same.

    # NtVer=(NETLOGON_NT_VERSION_IP|NETLOGON_NT_VERSION_WITH_CLOSEST_SITE|
    #        NETLOGON_NT_VERSION_5EX) [0x20000014]
    expr = "(&(DnsDomain=%s.)(User=%s)(NtVer=\\14\\00\\00\\20))" % (
        samdb.domain_dns_name(),
        hostname)
    res = samdb.search(
        base='',
        scope=ldb.SCOPE_BASE,
        expression=expr,
        attrs=["Netlogon"])
    if res.count != 1:
        raise RuntimeError('site_dn_for_machine: No result')

    samlogon_response = ndr_unpack(nbt.netlogon_samlogon_response,
                                   bytes(res.msgs[0]['Netlogon'][0]))
    if not (samlogon_response.ntver & nbt.NETLOGON_NT_VERSION_5EX):
        raise RuntimeError('site_dn_for_machine: Invalid NtVer in '
                           + 'netlogon_samlogon_response')

    # We want NETLOGON_NT_VERSION_5EX out of the union!
    samlogon_response.ntver = nbt.NETLOGON_NT_VERSION_5EX
    samlogon_response_ex = samlogon_response.data

    client_site = "Default-First-Site-Name"
    if (samlogon_response_ex.client_site
            and len(samlogon_response_ex.client_site) > 1):
        client_site = samlogon_response_ex.client_site

    site_dn = samdb.get_config_basedn()
    site_dn.add_child("CN=Sites")
    site_dn.add_child("CN=%s" % (client_site))

    return site_dn



def get_gpo_list(dc_hostname, creds, lp, username):
    """Get the full list of GROUP_POLICY_OBJECTs for a given username.
    Push GPOs to gpo_list so that the traversal order of the list matches
    the order of application:
    (L)ocal (S)ite (D)omain (O)rganizational(U)nit
    For different domains and OUs: parent-to-child.
    Within same level of domains and OUs: Link order.
    Since GPOs are pushed to the front of gpo_list, GPOs have to be
    pushed in the opposite order of application (OUs first, local last,
    child-to-parent).
    Forced GPOs are appended in the end since they override all others.
    """
    gpo_list = []
    forced_gpo_list = []
    url = 'ldap://' + dc_hostname
    samdb = SamDB(url=url,
                  session_info=system_session(),
                  credentials=creds, lp=lp)
    # username is DOM\\SAM, but get_gpo_list expects SAM
    uac, dn = find_samaccount(samdb, username.split('\\')[-1])
    add_only_forced_gpos = False

    # Fetch the security token
    session_info_flags = (AUTH_SESSION_INFO_DEFAULT_GROUPS |
                          AUTH_SESSION_INFO_AUTHENTICATED)
    if url.startswith('ldap'):
        session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES
    session = samba.auth.user_session(samdb, lp_ctx=lp, dn=dn,
                                      session_info_flags=session_info_flags)
    gpo_list_machine = False
    if uac & UF_WORKSTATION_TRUST_ACCOUNT or uac & UF_SERVER_TRUST_ACCOUNT:
        gpo_list_machine = True
        token = merge_with_system_token(session.security_token)
    else:
        token = session.security_token

    # (O)rganizational(U)nit
    parent_dn = dn.parent()
    while True:
        if str(parent_dn) == str(samdb.get_default_basedn().parent()):
            break

        # An account can be a member of more OUs
        if parent_dn.get_component_name(0) == 'OU':
            try:
                log.debug("get_gpo_list: query OU: [%s] for GPOs" % parent_dn)
                gp_link = get_gpo_link(samdb, parent_dn)
            except ldb.LdbError as e:
                (enum, estr) = e.args
                log.debug(estr)
            else:
                add_gplink_to_gpo_list(samdb, gpo_list, forced_gpo_list,
                                       parent_dn, gp_link,
                                       gpo.GP_LINK_OU,
                                       add_only_forced_gpos, token)

                # block inheritance from now on
                if gp_link.gp_opts & GPO_BLOCK_INHERITANCE:
                    add_only_forced_gpos = True

        parent_dn = parent_dn.parent()

    # (D)omain
    parent_dn = dn.parent()
    while True:
        if str(parent_dn) == str(samdb.get_default_basedn().parent()):
            break

        # An account can just be a member of one domain
        if parent_dn.get_component_name(0) == 'DC':
            try:
                log.debug("get_gpo_list: query DC: [%s] for GPOs" % parent_dn)
                gp_link = get_gpo_link(samdb, parent_dn)
            except ldb.LdbError as e:
                (enum, estr) = e.args
                log.debug(estr)
            else:
                add_gplink_to_gpo_list(samdb, gpo_list, forced_gpo_list,
                                       parent_dn, gp_link,
                                       gpo.GP_LINK_DOMAIN,
                                       add_only_forced_gpos, token)

                # block inheritance from now on
                if gp_link.gp_opts & GPO_BLOCK_INHERITANCE:
                    add_only_forced_gpos = True

        parent_dn = parent_dn.parent()

    # (S)ite
    if gpo_list_machine:
        try:
            site_dn = site_dn_for_machine(samdb, dc_hostname, lp, creds, username)

            try:
                log.debug("get_gpo_list: query SITE: [%s] for GPOs" % site_dn)
                gp_link = get_gpo_link(samdb, site_dn)
            except ldb.LdbError as e:
                (enum, estr) = e.args
                log.debug(estr)
            else:
                add_gplink_to_gpo_list(samdb, gpo_list, forced_gpo_list,
                                       site_dn, gp_link,
                                       gpo.GP_LINK_SITE,
                                       add_only_forced_gpos, token)
        except ldb.LdbError:
            # [MS-GPOL] 3.2.5.1.4 Site Search: If the method returns
            # ERROR_NO_SITENAME, the remainder of this message MUST be skipped
            # and the protocol sequence MUST continue at GPO Search
            pass

    # (L)ocal
    gpo_list.insert(0, gpo.GROUP_POLICY_OBJECT("Local Policy",
                                               "Local Policy",
                                               gpo.GP_LINK_LOCAL))

    # Append |forced_gpo_list| at the end of |gpo_list|,
    # so that forced GPOs are applied on top of non enforced GPOs.
    return gpo_list+forced_gpo_list


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
    for gpo_obj in gpos:
        if not gpo_obj.file_sys_path:
            continue
        cache_gpo_dir(conn, cache_path, check_safe_path(gpo_obj.file_sys_path))


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
                drop_privileges(username, ext.process_group_policy,
                                del_gpos, changed_gpos)
        except Exception as e:
            log.error('Failed to apply extension  %s' % str(ext))
            _, _, tb = sys.exc_info()
            filename, line_number, _, _ = traceback.extract_tb(tb)[-1]
            log.error('%s:%d: %s: %s' % (filename, line_number,
                                         type(e).__name__, str(e)))
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
    for gpo_obj in gpos:
        if gpo_obj.display_name.strip() == 'Local Policy':
            continue # We never apply local policy
        print('GPO: %s' % gpo_obj.display_name)
        print('='*term_width)
        for ext in gp_extensions:
            ext = ext(lp, creds, username, store)
            cse_name_m = re.findall(r"'([\w\.]+)'", str(type(ext)))
            if len(cse_name_m) > 0:
                cse_name = cse_name_m[-1].split('.')[-1]
            else:
                cse_name = ext.__module__.split('.')[-1]
            print('  CSE: %s' % cse_name)
            print('  ' + ('-'*int(term_width/2)))
            for section, settings in ext.rsop(gpo_obj).items():
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
    """
    Set current process privileges
    """

    os.setegid(gid)
    os.seteuid(uid)


def drop_privileges(username, func, *args):
    """
    Run supplied function with privileges for specified username.
    """
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

def expand_pref_variables(text, gpt_path, lp, username=None):
    utc_dt = datetime.utcnow()
    dt = datetime.now()
    cache_path = lp.cache_path(os.path.join('gpo_cache'))
    # These are all the possible preference variables that MS supports. The
    # variables set to 'None' here are currently unsupported by Samba, and will
    # prevent the individual policy from applying.
    variables = { 'AppDataDir': os.path.expanduser('~/.config'),
                  'BinaryComputerSid': None,
                  'BinaryUserSid': None,
                  'CommonAppdataDir': None,
                  'CommonDesktopDir': None,
                  'CommonFavoritesDir': None,
                  'CommonProgramsDir': None,
                  'CommonStartUpDir': None,
                  'ComputerName': lp.get('netbios name'),
                  'CurrentProccessId': None,
                  'CurrentThreadId': None,
                  'DateTime': utc_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                  'DateTimeEx': str(utc_dt),
                  'DesktopDir': os.path.expanduser('~/Desktop'),
                  'DomainName': lp.get('realm'),
                  'FavoritesDir': None,
                  'GphPath': None,
                  'GptPath': os.path.join(cache_path,
                                          check_safe_path(gpt_path).upper()),
                  'GroupPolicyVersion': None,
                  'LastDriveMapped': None,
                  'LastError': None,
                  'LastErrorText': None,
                  'LdapComputerSid': None,
                  'LdapUserSid': None,
                  'LocalTime': dt.strftime('%H:%M:%S'),
                  'LocalTimeEx': dt.strftime('%H:%M:%S.%f'),
                  'LogonDomain': lp.get('realm'),
                  'LogonServer': None,
                  'LogonUser': username,
                  'LogonUserSid': None,
                  'MacAddress': None,
                  'NetPlacesDir': None,
                  'OsVersion': None,
                  'ProgramFilesDir': None,
                  'ProgramsDir': None,
                  'RecentDocumentsDir': None,
                  'ResultCode': None,
                  'ResultText': None,
                  'ReversedComputerSid': None,
                  'ReversedUserSid': None,
                  'SendToDir': None,
                  'StartMenuDir': None,
                  'StartUpDir': None,
                  'SystemDir': None,
                  'SystemDrive': '/',
                  'TempDir': '/tmp',
                  'TimeStamp': str(datetime.timestamp(dt)),
                  'TraceFile': None,
                  'WindowsDir': None
    }
    for exp_var, val in variables.items():
        exp_var_fmt = '%%%s%%' % exp_var
        if exp_var_fmt in text:
            if val is None:
                raise NameError('Expansion variable %s is undefined' % exp_var)
            text = text.replace(exp_var_fmt, val)
    return text
