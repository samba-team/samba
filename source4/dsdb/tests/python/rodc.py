#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import optparse
import sys
import os
import base64
import random
import re
import uuid

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import drsblobs

import time


class RodcTestException(Exception):
    pass


class RodcTests(samba.tests.TestCase):

    def setUp(self):
        super(RodcTests, self).setUp()
        self.samdb = SamDB(HOST, credentials=CREDS,
                           session_info=system_session(LP), lp=LP)

        self.base_dn = self.samdb.domain_dn()

        root = self.samdb.search(base='', scope=ldb.SCOPE_BASE,
                                 attrs=['dsServiceName'])
        self.service = root[0]['dsServiceName'][0]
        self.tag = uuid.uuid4().hex

    def test_add_replicated_objects(self):
        for o in (
                {
                    'dn': "ou=%s1,%s" % (self.tag, self.base_dn),
                    "objectclass": "organizationalUnit"
                },
                {
                    'dn': "cn=%s2,%s" % (self.tag, self.base_dn),
                    "objectclass": "user"
                },
                {
                    'dn': "cn=%s3,%s" % (self.tag, self.base_dn),
                    "objectclass": "group"
                },
                {
                    'dn': "cn=%s4,%s" % (self.tag, self.service),
                    "objectclass": "NTDSConnection",
                    'enabledConnection': 'TRUE',
                    'fromServer': self.base_dn,
                    'options': '0'
                },
        ):
            try:
                self.samdb.add(o)
                self.fail("Failed to fail to add %s" % o['dn'])
            except ldb.LdbError as e:
                (ecode, emsg) = e.args
                if ecode != ldb.ERR_REFERRAL:
                    print(emsg)
                    self.fail("Adding %s: ldb error: %s %s, wanted referral" %
                              (o['dn'], ecode, emsg))
                else:
                    m = re.search(r'(ldap://[^>]+)>', emsg)
                    if m is None:
                        self.fail("referral seems not to refer to anything")
                    address = m.group(1)

                    try:
                        tmpdb = SamDB(address, credentials=CREDS,
                                      session_info=system_session(LP), lp=LP)
                        tmpdb.add(o)
                        tmpdb.delete(o['dn'])
                    except ldb.LdbError as e:
                        self.fail("couldn't modify referred location %s" %
                                  address)

                    if address.lower().startswith(self.samdb.domain_dns_name()):
                        self.fail("referral address did not give a specific DC")

    def test_modify_replicated_attributes(self):
        # some timestamp ones
        dn = 'CN=Guest,CN=Users,' + self.base_dn
        value = 'hallooo'
        for attr in ['carLicense', 'middleName']:
            msg = ldb.Message()
            msg.dn = ldb.Dn(self.samdb, dn)
            msg[attr] = ldb.MessageElement(value,
                                           ldb.FLAG_MOD_REPLACE,
                                           attr)
            try:
                self.samdb.modify(msg)
                self.fail("Failed to fail to modify %s %s" % (dn, attr))
            except ldb.LdbError as e1:
                (ecode, emsg) = e1.args
                if ecode != ldb.ERR_REFERRAL:
                    self.fail("Failed to REFER when trying to modify %s %s" %
                              (dn, attr))
                else:
                    m = re.search(r'(ldap://[^>]+)>', emsg)
                    if m is None:
                        self.fail("referral seems not to refer to anything")
                    address = m.group(1)

                    try:
                        tmpdb = SamDB(address, credentials=CREDS,
                                      session_info=system_session(LP), lp=LP)
                        tmpdb.modify(msg)
                    except ldb.LdbError as e:
                        self.fail("couldn't modify referred location %s" %
                                  address)

                    if address.lower().startswith(self.samdb.domain_dns_name()):
                        self.fail("referral address did not give a specific DC")

    def test_modify_nonreplicated_attributes(self):
        # some timestamp ones
        dn = 'CN=Guest,CN=Users,' + self.base_dn
        value = '123456789'
        for attr in ['badPwdCount', 'lastLogon', 'lastLogoff']:
            m = ldb.Message()
            m.dn = ldb.Dn(self.samdb, dn)
            m[attr] = ldb.MessageElement(value,
                                         ldb.FLAG_MOD_REPLACE,
                                         attr)
            # Windows refers these ones even though they are non-replicated
            try:
                self.samdb.modify(m)
                self.fail("Failed to fail to modify %s %s" % (dn, attr))
            except ldb.LdbError as e2:
                (ecode, emsg) = e2.args
                if ecode != ldb.ERR_REFERRAL:
                    self.fail("Failed to REFER when trying to modify %s %s" %
                              (dn, attr))
                else:
                    m = re.search(r'(ldap://[^>]+)>', emsg)
                    if m is None:
                        self.fail("referral seems not to refer to anything")
                    address = m.group(1)

                    if address.lower().startswith(self.samdb.domain_dns_name()):
                        self.fail("referral address did not give a specific DC")

    def test_modify_nonreplicated_reps_attributes(self):
        # some timestamp ones
        dn = self.base_dn

        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, dn)
        attr = 'repsFrom'

        res = self.samdb.search(dn, scope=ldb.SCOPE_BASE,
                                attrs=['repsFrom'])
        rep = ndr_unpack(drsblobs.repsFromToBlob, res[0]['repsFrom'][0],
                         allow_remaining=True)
        rep.ctr.result_last_attempt = -1
        value = ndr_pack(rep)

        m[attr] = ldb.MessageElement(value,
                                     ldb.FLAG_MOD_REPLACE,
                                     attr)
        try:
            self.samdb.modify(m)
            self.fail("Failed to fail to modify %s %s" % (dn, attr))
        except ldb.LdbError as e3:
            (ecode, emsg) = e3.args
            if ecode != ldb.ERR_REFERRAL:
                self.fail("Failed to REFER when trying to modify %s %s" %
                          (dn, attr))
            else:
                m = re.search(r'(ldap://[^>]+)>', emsg)
                if m is None:
                    self.fail("referral seems not to refer to anything")
                address = m.group(1)

                if address.lower().startswith(self.samdb.domain_dns_name()):
                    self.fail("referral address did not give a specific DC")

    def test_delete_special_objects(self):
        dn = 'CN=Guest,CN=Users,' + self.base_dn
        try:
            self.samdb.delete(dn)
            self.fail("Failed to fail to delete %s" % (dn))
        except ldb.LdbError as e4:
            (ecode, emsg) = e4.args
            if ecode != ldb.ERR_REFERRAL:
                print(ecode, emsg)
                self.fail("Failed to REFER when trying to delete %s" % dn)
            else:
                m = re.search(r'(ldap://[^>]+)>', emsg)
                if m is None:
                    self.fail("referral seems not to refer to anything")
                address = m.group(1)

                if address.lower().startswith(self.samdb.domain_dns_name()):
                    self.fail("referral address did not give a specific DC")

    def test_no_delete_nonexistent_objects(self):
        dn = 'CN=does-not-exist-%s,CN=Users,%s' % (self.tag, self.base_dn)
        try:
            self.samdb.delete(dn)
            self.fail("Failed to fail to delete %s" % (dn))
        except ldb.LdbError as e5:
            (ecode, emsg) = e5.args
            if ecode != ldb.ERR_NO_SUCH_OBJECT:
                print(ecode, emsg)
                self.fail("Failed to NO_SUCH_OBJECT when trying to delete "
                          "%s (which does not exist)" % dn)



def main():
    global HOST, CREDS, LP
    parser = optparse.OptionParser("rodc.py [options] <host>")

    sambaopts = options.SambaOptions(parser)
    versionopts = options.VersionOptions(parser)
    credopts = options.CredentialsOptions(parser)
    subunitopts = SubunitOptions(parser)

    parser.add_option_group(sambaopts)
    parser.add_option_group(versionopts)
    parser.add_option_group(credopts)
    parser.add_option_group(subunitopts)

    opts, args = parser.parse_args()

    LP = sambaopts.get_loadparm()
    CREDS = credopts.get_credentials(LP)

    try:
        HOST = args[0]
    except IndexError:
        parser.print_usage()
        sys.exit(1)

    if "://" not in HOST:
        if os.path.isfile(HOST):
            HOST = "tdb://%s" % HOST
        else:
            HOST = "ldap://%s" % HOST

    TestProgram(module=__name__, opts=subunitopts)

main()
