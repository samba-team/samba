# Helpers for provision stuff
# Copyright (C) Matthieu Patou <mat@matws.net> 2009-2012
#
# Based on provision a Samba4 server by
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
#
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

"""Helpers used for upgrading between different database formats."""

import os
import re
import shutil
import samba

from samba import Ldb, version, ntacls
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
import ldb
from samba.provision import (provision_paths_from_lp,
                            getpolicypath, set_gpos_acl, create_gpo_struct,
                            provision, ProvisioningError,
                            setsysvolacl, secretsdb_self_join)
from samba.provision.common import FILL_FULL
from samba.dcerpc import xattr, drsblobs, security
from samba.dcerpc.misc import SEC_CHAN_BDC
from samba.ndr import ndr_unpack
from samba.samdb import SamDB
from samba import _glue
import tempfile

# All the ldb related to registry are commented because the path for them is
# relative in the provisionPath object
# And so opening them create a file in the current directory which is not what
# we want
# I still keep them commented because I plan soon to make more cleaner
ERROR =     -1
SIMPLE =     0x00
CHANGE =     0x01
CHANGESD =     0x02
GUESS =     0x04
PROVISION =    0x08
CHANGEALL =    0xff

hashAttrNotCopied = set(["dn", "whenCreated", "whenChanged", "objectGUID",
    "uSNCreated", "replPropertyMetaData", "uSNChanged", "parentGUID",
    "objectCategory", "distinguishedName", "nTMixedDomain",
    "showInAdvancedViewOnly", "instanceType", "msDS-Behavior-Version",
    "nextRid", "cn", "versionNumber", "lmPwdHistory", "pwdLastSet",
    "ntPwdHistory", "unicodePwd","dBCSPwd", "supplementalCredentials",
    "gPCUserExtensionNames", "gPCMachineExtensionNames","maxPwdAge", "secret",
    "possibleInferiors", "privilege", "sAMAccountType"])


class ProvisionLDB(object):

    def __init__(self):
        self.sam = None
        self.secrets = None
        self.idmap = None
        self.privilege = None
        self.hkcr = None
        self.hkcu = None
        self.hku = None
        self.hklm = None

    def dbs(self):
        return (self.sam, self.secrets, self.idmap, self.privilege)

    def startTransactions(self):
        for db in self.dbs():
            db.transaction_start()
# TO BE DONE
#        self.hkcr.transaction_start()
#        self.hkcu.transaction_start()
#        self.hku.transaction_start()
#        self.hklm.transaction_start()

    def groupedRollback(self):
        ok = True
        for db in self.dbs():
            try:
                db.transaction_cancel()
            except Exception:
                ok = False
        return ok
# TO BE DONE
#        self.hkcr.transaction_cancel()
#        self.hkcu.transaction_cancel()
#        self.hku.transaction_cancel()
#        self.hklm.transaction_cancel()

    def groupedCommit(self):
        try:
            for db in self.dbs():
                db.transaction_prepare_commit()
        except Exception:
            return self.groupedRollback()
# TO BE DONE
#        self.hkcr.transaction_prepare_commit()
#        self.hkcu.transaction_prepare_commit()
#        self.hku.transaction_prepare_commit()
#        self.hklm.transaction_prepare_commit()
        try:
            for db in self.dbs():
                db.transaction_commit()
        except Exception:
            return self.groupedRollback()

# TO BE DONE
#        self.hkcr.transaction_commit()
#        self.hkcu.transaction_commit()
#        self.hku.transaction_commit()
#        self.hklm.transaction_commit()
        return True


def get_ldbs(paths, creds, session, lp):
    """Return LDB object mapped on most important databases

    :param paths: An object holding the different importants paths for provision object
    :param creds: Credential used for openning LDB files
    :param session: Session to use for openning LDB files
    :param lp: A loadparam object
    :return: A ProvisionLDB object that contains LDB object for the different LDB files of the provision"""

    ldbs = ProvisionLDB()

    ldbs.sam = SamDB(paths.samdb, session_info=session, credentials=creds, lp=lp, options=["modules:samba_dsdb"])
    ldbs.secrets = Ldb(paths.secrets, session_info=session, credentials=creds, lp=lp)
    ldbs.idmap = Ldb(paths.idmapdb, session_info=session, credentials=creds, lp=lp)
    ldbs.privilege = Ldb(paths.privilege, session_info=session, credentials=creds, lp=lp)
#    ldbs.hkcr = Ldb(paths.hkcr, session_info=session, credentials=creds, lp=lp)
#    ldbs.hkcu = Ldb(paths.hkcu, session_info=session, credentials=creds, lp=lp)
#    ldbs.hku = Ldb(paths.hku, session_info=session, credentials=creds, lp=lp)
#    ldbs.hklm = Ldb(paths.hklm, session_info=session, credentials=creds, lp=lp)

    return ldbs


def usn_in_range(usn, range):
    """Check if the usn is in one of the range provided.
    To do so, the value is checked to be between the lower bound and
    higher bound of a range

    :param usn: A integer value corresponding to the usn that we want to update
    :param range: A list of integer representing ranges, lower bounds are in
                  the even indices, higher in odd indices
    :return: True if the usn is in one of the range, False otherwise
    """

    idx = 0
    cont = True
    ok = False
    while cont:
        if idx ==  len(range):
            cont = False
            continue
        if usn < int(range[idx]):
            if idx %2 == 1:
                ok = True
            cont = False
        if usn == int(range[idx]):
            cont = False
            ok = True
        idx = idx + 1
    return ok


def get_paths(param, targetdir=None, smbconf=None):
    """Get paths to important provision objects (smb.conf, ldb files, ...)

    :param param: Param object
    :param targetdir: Directory where the provision is (or will be) stored
    :param smbconf: Path to the smb.conf file
    :return: A list with the path of important provision objects"""
    if targetdir is not None:
        if not os.path.exists(targetdir):
            os.mkdir(targetdir)
        etcdir = os.path.join(targetdir, "etc")
        if not os.path.exists(etcdir):
            os.makedirs(etcdir)
        smbconf = os.path.join(etcdir, "smb.conf")
    if smbconf is None:
        smbconf = param.default_path()

    if not os.path.exists(smbconf):
        raise ProvisioningError("Unable to find smb.conf")

    lp = param.LoadParm()
    lp.load(smbconf)
    paths = provision_paths_from_lp(lp, lp.get("realm"))
    return paths

def update_policyids(names, samdb):
    """Update policy ids that could have changed after sam update

    :param names: List of key provision parameters
    :param samdb: An Ldb object conntected with the sam DB
    """
    # policy guid
    res = samdb.search(expression="(displayName=Default Domain Policy)",
                        base="CN=Policies,CN=System," + str(names.rootdn),
                        scope=SCOPE_ONELEVEL, attrs=["cn","displayName"])
    names.policyid = str(res[0]["cn"]).replace("{","").replace("}","")
    # dc policy guid
    res2 = samdb.search(expression="(displayName=Default Domain Controllers"
                                   " Policy)",
                            base="CN=Policies,CN=System," + str(names.rootdn),
                            scope=SCOPE_ONELEVEL, attrs=["cn","displayName"])
    if len(res2) == 1:
        names.policyid_dc = str(res2[0]["cn"]).replace("{","").replace("}","")
    else:
        names.policyid_dc = None


def newprovision(names, session, smbconf, provdir, logger):
    """Create a new provision.

    This provision will be the reference for knowing what has changed in the
    since the latest upgrade in the current provision

    :param names: List of provision parameters
    :param creds: Credentials for the authentification
    :param session: Session object
    :param smbconf: Path to the smb.conf file
    :param provdir: Directory where the provision will be stored
    :param logger: A Logger
    """
    if os.path.isdir(provdir):
        shutil.rmtree(provdir)
    os.mkdir(provdir)
    logger.info("Provision stored in %s", provdir)
    return provision(logger, session, smbconf=smbconf,
            targetdir=provdir, samdb_fill=FILL_FULL, realm=names.realm,
            domain=names.domain, domainguid=names.domainguid,
            domainsid=names.domainsid, ntdsguid=names.ntdsguid,
            policyguid=names.policyid, policyguid_dc=names.policyid_dc,
            hostname=names.netbiosname.lower(), hostip=None, hostip6=None,
            invocationid=names.invocation, adminpass=names.adminpass,
            krbtgtpass=None, machinepass=None, dnspass=None, root=None,
            nobody=None, users=None,
            serverrole="domain controller",
            backend_type=None, ldapadminpass=None, ol_mmr_urls=None,
            slapd_path=None,
            dom_for_fun_level=names.domainlevel, dns_backend=names.dns_backend,
            useeadb=True, use_ntvfs=True)


def dn_sort(x, y):
    """Sorts two DNs in the lexicographical order it and put higher level DN
    before.

    So given the dns cn=bar,cn=foo and cn=foo the later will be return as
    smaller

    :param x: First object to compare
    :param y: Second object to compare
    """
    p = re.compile(r'(?<!\\), ?')
    tab1 = p.split(str(x))
    tab2 = p.split(str(y))
    minimum = min(len(tab1), len(tab2))
    len1 = len(tab1)-1
    len2 = len(tab2)-1
    # Note: python range go up to upper limit but do not include it
    for i in range(0, minimum):
        ret = cmp(tab1[len1-i], tab2[len2-i])
        if ret != 0:
            return ret
        else:
            if i == minimum-1:
                assert len1!=len2,"PB PB PB" + " ".join(tab1)+" / " + " ".join(tab2)
                if len1 > len2:
                    return 1
                else:
                    return -1
    return ret


def identic_rename(ldbobj, dn):
    """Perform a back and forth rename to trigger renaming on attribute that
    can't be directly modified.

    :param lbdobj: An Ldb Object
    :param dn: DN of the object to manipulate
    """
    (before, after) = str(dn).split('=', 1)
    # we need to use relax to avoid the subtree_rename constraints
    ldbobj.rename(dn, ldb.Dn(ldbobj, "%s=foo%s" % (before, after)), ["relax:0"])
    ldbobj.rename(ldb.Dn(ldbobj, "%s=foo%s" % (before, after)), dn, ["relax:0"])


def update_secrets(newsecrets_ldb, secrets_ldb, messagefunc):
    """Update secrets.ldb

    :param newsecrets_ldb: An LDB object that is connected to the secrets.ldb
        of the reference provision
    :param secrets_ldb: An LDB object that is connected to the secrets.ldb
        of the updated provision
    """

    messagefunc(SIMPLE, "Update of secrets.ldb")
    reference = newsecrets_ldb.search(base="@MODULES", scope=SCOPE_BASE)
    current = secrets_ldb.search(base="@MODULES", scope=SCOPE_BASE)
    assert reference, "Reference modules list can not be empty"
    if len(current) == 0:
        # No modules present
        delta = secrets_ldb.msg_diff(ldb.Message(), reference[0])
        delta.dn = reference[0].dn
        secrets_ldb.add(reference[0])
    else:
        delta = secrets_ldb.msg_diff(current[0], reference[0])
        delta.dn = current[0].dn
        secrets_ldb.modify(delta)

    reference = newsecrets_ldb.search(expression="objectClass=top", base="",
                                        scope=SCOPE_SUBTREE, attrs=["dn"])
    current = secrets_ldb.search(expression="objectClass=top", base="",
                                        scope=SCOPE_SUBTREE, attrs=["dn"])
    hash_new = {}
    hash = {}
    listMissing = []
    listPresent = []

    empty = ldb.Message()
    for i in range(0, len(reference)):
        hash_new[str(reference[i]["dn"]).lower()] = reference[i]["dn"]

    # Create a hash for speeding the search of existing object in the
    # current provision
    for i in range(0, len(current)):
        hash[str(current[i]["dn"]).lower()] = current[i]["dn"]

    for k in hash_new.keys():
        if not hash.has_key(k):
            listMissing.append(hash_new[k])
        else:
            listPresent.append(hash_new[k])

    for entry in listMissing:
        reference = newsecrets_ldb.search(expression="distinguishedName=%s" % entry,
                                            base="", scope=SCOPE_SUBTREE)
        current = secrets_ldb.search(expression="distinguishedName=%s" % entry,
                                            base="", scope=SCOPE_SUBTREE)
        delta = secrets_ldb.msg_diff(empty, reference[0])
        for att in hashAttrNotCopied:
            delta.remove(att)
        messagefunc(CHANGE, "Entry %s is missing from secrets.ldb" %
                    reference[0].dn)
        for att in delta:
            messagefunc(CHANGE, " Adding attribute %s" % att)
        delta.dn = reference[0].dn
        secrets_ldb.add(delta)

    for entry in listPresent:
        reference = newsecrets_ldb.search(expression="distinguishedName=%s" % entry,
                                            base="", scope=SCOPE_SUBTREE)
        current = secrets_ldb.search(expression="distinguishedName=%s" % entry, base="",
                                            scope=SCOPE_SUBTREE)
        delta = secrets_ldb.msg_diff(current[0], reference[0])
        for att in hashAttrNotCopied:
            delta.remove(att)
        for att in delta:
            if att == "name":
                messagefunc(CHANGE, "Found attribute name on  %s,"
                                    " must rename the DN" % (current[0].dn))
                identic_rename(secrets_ldb, reference[0].dn)
            else:
                delta.remove(att)

    for entry in listPresent:
        reference = newsecrets_ldb.search(expression="distinguishedName=%s" % entry, base="",
                                            scope=SCOPE_SUBTREE)
        current = secrets_ldb.search(expression="distinguishedName=%s" % entry, base="",
                                            scope=SCOPE_SUBTREE)
        delta = secrets_ldb.msg_diff(current[0], reference[0])
        for att in hashAttrNotCopied:
            delta.remove(att)
        for att in delta:
            if att == "msDS-KeyVersionNumber":
                delta.remove(att)
            if att != "dn":
                messagefunc(CHANGE,
                            "Adding/Changing attribute %s to %s" %
                            (att, current[0].dn))

        delta.dn = current[0].dn
        secrets_ldb.modify(delta)

    res2 = secrets_ldb.search(expression="(samaccountname=dns)",
                                scope=SCOPE_SUBTREE, attrs=["dn"])

    if len(res2) == 1:
            messagefunc(SIMPLE, "Remove old dns account")
            secrets_ldb.delete(res2[0]["dn"])


def getOEMInfo(samdb, rootdn):
    """Return OEM Information on the top level Samba4 use to store version
    info in this field

    :param samdb: An LDB object connect to sam.ldb
    :param rootdn: Root DN of the domain
    :return: The content of the field oEMInformation (if any)
    """
    res = samdb.search(expression="(objectClass=*)", base=str(rootdn),
                            scope=SCOPE_BASE, attrs=["dn", "oEMInformation"])
    if len(res) > 0 and res[0].get("oEMInformation"):
        info = res[0]["oEMInformation"]
        return info
    else:
        return ""


def updateOEMInfo(samdb, rootdn):
    """Update the OEMinfo field to add information about upgrade

    :param samdb: an LDB object connected to the sam DB
    :param rootdn: The string representation of the root DN of
        the provision (ie. DC=...,DC=...)
    """
    res = samdb.search(expression="(objectClass=*)", base=rootdn,
                            scope=SCOPE_BASE, attrs=["dn", "oEMInformation"])
    if len(res) > 0:
        if res[0].get("oEMInformation"):
            info = str(res[0]["oEMInformation"])
        else:
            info = ""
        info = "%s, upgrade to %s" % (info, version)
        delta = ldb.Message()
        delta.dn = ldb.Dn(samdb, str(res[0]["dn"]))
        delta["oEMInformation"] = ldb.MessageElement(info, ldb.FLAG_MOD_REPLACE,
                                                        "oEMInformation" )
        samdb.modify(delta)

def update_gpo(paths, samdb, names, lp, message):
    """Create missing GPO file object if needed
    """
    dir = getpolicypath(paths.sysvol, names.dnsdomain, names.policyid)
    if not os.path.isdir(dir):
        create_gpo_struct(dir)

    if names.policyid_dc is None:
        raise ProvisioningError("Policy ID for Domain controller is missing")
    dir = getpolicypath(paths.sysvol, names.dnsdomain, names.policyid_dc)
    if not os.path.isdir(dir):
        create_gpo_struct(dir)

def increment_calculated_keyversion_number(samdb, rootdn, hashDns):
    """For a given hash associating dn and a number, this function will
    update the replPropertyMetaData of each dn in the hash, so that the
    calculated value of the msDs-KeyVersionNumber is equal or superior to the
    one associated to the given dn.

    :param samdb: An SamDB object pointing to the sam
    :param rootdn: The base DN where we want to start
    :param hashDns: A hash with dn as key and number representing the
                 minimum value of msDs-KeyVersionNumber that we want to
                 have
    """
    entry = samdb.search(expression='(objectClass=user)',
                         base=ldb.Dn(samdb,str(rootdn)),
                         scope=SCOPE_SUBTREE, attrs=["msDs-KeyVersionNumber"],
                         controls=["search_options:1:2"])
    done = 0
    hashDone = {}
    if len(entry) == 0:
        raise ProvisioningError("Unable to find msDs-KeyVersionNumber")
    else:
        for e in entry:
            if hashDns.has_key(str(e.dn).lower()):
                val = e.get("msDs-KeyVersionNumber")
                if not val:
                    val = "0"
                version = int(str(hashDns[str(e.dn).lower()]))
                if int(str(val)) < version:
                    done = done + 1
                    samdb.set_attribute_replmetadata_version(str(e.dn),
                                                              "unicodePwd",
                                                              version, True)
def delta_update_basesamdb(refsampath, sampath, creds, session, lp, message):
    """Update the provision container db: sam.ldb
    This function is aimed for alpha9 and newer;

    :param refsampath: Path to the samdb in the reference provision
    :param sampath: Path to the samdb in the upgraded provision
    :param creds: Credential used for openning LDB files
    :param session: Session to use for openning LDB files
    :param lp: A loadparam object
    :return: A msg_diff object with the difference between the @ATTRIBUTES
             of the current provision and the reference provision
    """

    message(SIMPLE,
            "Update base samdb by searching difference with reference one")
    refsam = Ldb(refsampath, session_info=session, credentials=creds,
                    lp=lp, options=["modules:"])
    sam = Ldb(sampath, session_info=session, credentials=creds, lp=lp,
                options=["modules:"])

    empty = ldb.Message()
    deltaattr = None
    reference = refsam.search(expression="")

    for refentry in reference:
        entry = sam.search(expression="distinguishedName=%s" % refentry["dn"],
                            scope=SCOPE_SUBTREE)
        if not len(entry):
            delta = sam.msg_diff(empty, refentry)
            message(CHANGE, "Adding %s to sam db" % str(refentry.dn))
            if str(refentry.dn) == "@PROVISION" and\
                delta.get(samba.provision.LAST_PROVISION_USN_ATTRIBUTE):
                delta.remove(samba.provision.LAST_PROVISION_USN_ATTRIBUTE)
            delta.dn = refentry.dn
            sam.add(delta)
        else:
            delta = sam.msg_diff(entry[0], refentry)
            if str(refentry.dn) == "@ATTRIBUTES":
                deltaattr = sam.msg_diff(refentry, entry[0])
            if str(refentry.dn) == "@PROVISION" and\
                delta.get(samba.provision.LAST_PROVISION_USN_ATTRIBUTE):
                delta.remove(samba.provision.LAST_PROVISION_USN_ATTRIBUTE)
            if len(delta.items()) > 1:
                delta.dn = refentry.dn
                sam.modify(delta)

    return deltaattr


def construct_existor_expr(attrs):
    """Construct a exists or LDAP search expression.

    :param attrs: List of attribute on which we want to create the search
        expression.
    :return: A string representing the expression, if attrs is empty an
        empty string is returned
    """
    expr = ""
    if len(attrs) > 0:
        expr = "(|"
        for att in attrs:
            expr = "%s(%s=*)"%(expr,att)
        expr = "%s)"%expr
    return expr

def update_machine_account_password(samdb, secrets_ldb, names):
    """Update (change) the password of the current DC both in the SAM db and in
       secret one

    :param samdb: An LDB object related to the sam.ldb file of a given provision
    :param secrets_ldb: An LDB object related to the secrets.ldb file of a given
                        provision
    :param names: List of key provision parameters"""

    expression = "samAccountName=%s$" % names.netbiosname
    secrets_msg = secrets_ldb.search(expression=expression,
                                        attrs=["secureChannelType"])
    if int(secrets_msg[0]["secureChannelType"][0]) == SEC_CHAN_BDC:
        res = samdb.search(expression=expression, attrs=[])
        assert(len(res) == 1)

        msg = ldb.Message(res[0].dn)
        machinepass = samba.generate_random_password(128, 255)
        mputf16 = machinepass.encode('utf-16-le')
        msg["clearTextPassword"] = ldb.MessageElement(mputf16,
                                                ldb.FLAG_MOD_REPLACE,
                                                "clearTextPassword")
        samdb.modify(msg)

        res = samdb.search(expression=("samAccountName=%s$" % names.netbiosname),
                     attrs=["msDs-keyVersionNumber"])
        assert(len(res) == 1)
        kvno = int(str(res[0]["msDs-keyVersionNumber"]))
        secChanType = int(secrets_msg[0]["secureChannelType"][0])

        secretsdb_self_join(secrets_ldb, domain=names.domain,
                    realm=names.realm,
                    domainsid=names.domainsid,
                    dnsdomain=names.dnsdomain,
                    netbiosname=names.netbiosname,
                    machinepass=machinepass,
                    key_version_number=kvno,
                    secure_channel_type=secChanType)
    else:
        raise ProvisioningError("Unable to find a Secure Channel"
                                "of type SEC_CHAN_BDC")

def update_dns_account_password(samdb, secrets_ldb, names):
    """Update (change) the password of the dns both in the SAM db and in
       secret one

    :param samdb: An LDB object related to the sam.ldb file of a given provision
    :param secrets_ldb: An LDB object related to the secrets.ldb file of a given
                        provision
    :param names: List of key provision parameters"""

    expression = "samAccountName=dns-%s" % names.netbiosname
    secrets_msg = secrets_ldb.search(expression=expression)
    if len(secrets_msg) == 1:
        res = samdb.search(expression=expression, attrs=[])
        assert(len(res) == 1)

        msg = ldb.Message(res[0].dn)
        machinepass = samba.generate_random_password(128, 255)
        mputf16 = machinepass.encode('utf-16-le')
        msg["clearTextPassword"] = ldb.MessageElement(mputf16,
                                                ldb.FLAG_MOD_REPLACE,
                                                "clearTextPassword")

        samdb.modify(msg)

        res = samdb.search(expression=expression,
                     attrs=["msDs-keyVersionNumber"])
        assert(len(res) == 1)
        kvno = str(res[0]["msDs-keyVersionNumber"])

        msg = ldb.Message(secrets_msg[0].dn)
        msg["secret"] = ldb.MessageElement(machinepass,
                                                ldb.FLAG_MOD_REPLACE,
                                                "secret")
        msg["msDS-KeyVersionNumber"] = ldb.MessageElement(kvno,
                                                ldb.FLAG_MOD_REPLACE,
                                                "msDS-KeyVersionNumber")

        secrets_ldb.modify(msg)

def search_constructed_attrs_stored(samdb, rootdn, attrs):
    """Search a given sam DB for calculated attributes that are
    still stored in the db.

    :param samdb: An LDB object pointing to the sam
    :param rootdn: The base DN where the search should start
    :param attrs: A list of attributes to be searched
    :return: A hash with attributes as key and an array of
             array. Each array contains the dn and the associated
             values for this attribute as they are stored in the
             sam."""

    hashAtt = {}
    expr = construct_existor_expr(attrs)
    if expr == "":
        return hashAtt
    entry = samdb.search(expression=expr, base=ldb.Dn(samdb, str(rootdn)),
                         scope=SCOPE_SUBTREE, attrs=attrs,
                         controls=["search_options:1:2","bypassoperational:0"])
    if len(entry) == 0:
        # Nothing anymore
        return hashAtt

    for ent in entry:
        for att in attrs:
            if ent.get(att):
                if hashAtt.has_key(att):
                    hashAtt[att][str(ent.dn).lower()] = str(ent[att])
                else:
                    hashAtt[att] = {}
                    hashAtt[att][str(ent.dn).lower()] = str(ent[att])

    return hashAtt

def findprovisionrange(samdb, basedn):
    """ Find ranges of usn grouped by invocation id and then by timestamp
        rouned at 1 minute

        :param samdb: An LDB object pointing to the samdb
        :param basedn: The DN of the forest

        :return: A two level dictionary with invoication id as the
                first level, timestamp as the second one and then
                max, min, and number as subkeys, representing respectivily
                the maximum usn for the range, the minimum usn and the number
                of object with usn in this range.
    """
    nb_obj = 0
    hash_id = {}

    res = samdb.search(base=basedn, expression="objectClass=*",
                                    scope=ldb.SCOPE_SUBTREE,
                                    attrs=["replPropertyMetaData"],
                                    controls=["search_options:1:2"])

    for e in res:
        nb_obj = nb_obj + 1
        obj = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                            str(e["replPropertyMetaData"])).ctr

        for o in obj.array:
            # like a timestamp but with the resolution of 1 minute
            minutestamp =_glue.nttime2unix(o.originating_change_time)/60
            hash_ts = hash_id.get(str(o.originating_invocation_id))

            if hash_ts is None:
                ob = {}
                ob["min"] = o.originating_usn
                ob["max"] = o.originating_usn
                ob["num"] = 1
                ob["list"] = [str(e.dn)]
                hash_ts = {}
            else:
                ob = hash_ts.get(minutestamp)
                if ob is None:
                    ob = {}
                    ob["min"] = o.originating_usn
                    ob["max"] = o.originating_usn
                    ob["num"] = 1
                    ob["list"] = [str(e.dn)]
                else:
                    if ob["min"] > o.originating_usn:
                        ob["min"] = o.originating_usn
                    if ob["max"] < o.originating_usn:
                        ob["max"] = o.originating_usn
                    if not (str(e.dn) in ob["list"]):
                        ob["num"] = ob["num"] + 1
                        ob["list"].append(str(e.dn))
            hash_ts[minutestamp] = ob
            hash_id[str(o.originating_invocation_id)] = hash_ts

    return (hash_id, nb_obj)

def print_provision_ranges(dic, limit_print, dest, samdb_path, invocationid):
    """ print the differents ranges passed as parameter

        :param dic: A dictionnary as returned by findprovisionrange
        :param limit_print: minimum number of object in a range in order to print it
        :param dest: Destination directory
        :param samdb_path: Path to the sam.ldb file
        :param invoicationid: Invocation ID for the current provision
    """
    ldif = ""

    for id in dic:
        hash_ts = dic[id]
        sorted_keys = []
        sorted_keys.extend(hash_ts.keys())
        sorted_keys.sort()

        kept_record = []
        for k in sorted_keys:
            obj = hash_ts[k]
            if obj["num"] > limit_print:
                dt = _glue.nttime2string(_glue.unix2nttime(k*60))
                print "%s # of modification: %d  \tmin: %d max: %d" % (dt , obj["num"],
                                                                    obj["min"],
                                                                    obj["max"])
            if hash_ts[k]["num"] > 600:
                kept_record.append(k)

        # Let's try to concatenate consecutive block if they are in the almost same minutestamp
        for i in range(0, len(kept_record)):
            if i != 0:
                key1 = kept_record[i]
                key2 = kept_record[i-1]
                if key1 - key2 == 1:
                    # previous record is just 1 minute away from current
                    if int(hash_ts[key1]["min"]) == int(hash_ts[key2]["max"]) + 1:
                        # Copy the highest USN in the previous record
                        # and mark the current as skipped
                        hash_ts[key2]["max"] = hash_ts[key1]["max"]
                        hash_ts[key1]["skipped"] = True

        for k in kept_record:
                obj = hash_ts[k]
                if obj.get("skipped") is None:
                    ldif = "%slastProvisionUSN: %d-%d;%s\n" % (ldif, obj["min"],
                                obj["max"], id)

    if ldif != "":
        file = tempfile.mktemp(dir=dest, prefix="usnprov", suffix=".ldif")
        print
        print "To track the USNs modified/created by provision and upgrade proivsion,"
        print " the following ranges are proposed to be added to your provision sam.ldb: \n%s" % ldif
        print "We recommend to review them, and if it's correct to integrate the following ldif: %s in your sam.ldb" % file
        print "You can load this file like this: ldbadd -H %s %s\n"%(str(samdb_path),file)
        ldif = "dn: @PROVISION\nprovisionnerID: %s\n%s" % (invocationid, ldif)
        open(file,'w').write(ldif)

def int64range2str(value):
    """Display the int64 range stored in value as xxx-yyy

    :param value: The int64 range
    :return: A string of the representation of the range
    """

    lvalue = long(value)
    str = "%d-%d" % (lvalue&0xFFFFFFFF, lvalue>>32)
    return str
