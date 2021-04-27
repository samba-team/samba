# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2020-2021 Catalyst.Net Ltd
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

import sys
import os
from datetime import datetime
import tempfile

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"
from collections import namedtuple
import ldb
from ldb import SCOPE_BASE
from samba import generate_random_password
from samba.auth import system_session
from samba.credentials import Credentials, SPECIFIED, MUST_USE_KERBEROS
from samba.dcerpc import krb5pac, krb5ccache
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_NORMAL_ACCOUNT
from samba.ndr import ndr_pack, ndr_unpack
from samba.samdb import SamDB

from samba.tests import delete_force
from samba.tests.krb5.raw_testcase import RawKerberosTest
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    AD_IF_RELEVANT,
    AD_WIN2K_PAC,
    AES256_CTS_HMAC_SHA1_96,
    ARCFOUR_HMAC_MD5,
    KDC_ERR_PREAUTH_REQUIRED,
    KRB_AS_REP,
    KRB_TGS_REP,
    KRB_ERROR,
    KU_AS_REP_ENC_PART,
    KU_PA_ENC_TIMESTAMP,
    KU_TGS_REP_ENC_PART_SUB_KEY,
    KU_TICKET,
    NT_PRINCIPAL,
    NT_SRV_HST,
    PADATA_ENC_TIMESTAMP,
    PADATA_ETYPE_INFO2,
)

global_asn1_print = False
global_hexdump = False


class KDCBaseTest(RawKerberosTest):
    """ Base class for KDC tests.
    """

    @classmethod
    def setUpClass(cls):
        cls.lp = cls.get_loadparm(cls)
        cls.username = os.environ["USERNAME"]
        cls.password = os.environ["PASSWORD"]
        cls.host = os.environ["SERVER"]

        c = Credentials()
        c.set_username(cls.username)
        c.set_password(cls.password)
        try:
            realm = os.environ["REALM"]
            c.set_realm(realm)
        except KeyError:
            pass
        try:
            domain = os.environ["DOMAIN"]
            c.set_domain(domain)
        except KeyError:
            pass

        c.guess()

        cls.credentials = c

        cls.session = system_session()
        cls.ldb = SamDB(url="ldap://%s" % cls.host,
                        session_info=cls.session,
                        credentials=cls.credentials,
                        lp=cls.lp)
        # fetch the dnsHostName from the RootDse
        res = cls.ldb.search(
            base="", expression="", scope=SCOPE_BASE, attrs=["dnsHostName"])
        cls.dns_host_name = str(res[0]['dnsHostName'])

    def setUp(self):
        super().setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump
        self.accounts = []

    def tearDown(self):
        # Clean up any accounts created by create_account
        for dn in self.accounts:
            delete_force(self.ldb, dn)

    def create_account(self, name, machine_account=False, spn=None, upn=None):
        '''Create an account for testing.
           The dn of the created account is added to self.accounts,
           which is used by tearDown to clean up the created accounts.
        '''
        dn = "cn=%s,%s" % (name, self.ldb.domain_dn())

        # remove the account if it exists, this will happen if a previous test
        # run failed
        delete_force(self.ldb, dn)
        if machine_account:
            object_class = "computer"
            account_name = "%s$" % name
            account_control = str(UF_WORKSTATION_TRUST_ACCOUNT)
        else:
            object_class = "user"
            account_name = name
            account_control = str(UF_NORMAL_ACCOUNT)

        password = generate_random_password(32, 32)
        utf16pw = ('"%s"' % password).encode('utf-16-le')

        details = {
            "dn": dn,
            "objectclass": object_class,
            "sAMAccountName": account_name,
            "userAccountControl": account_control,
            "unicodePwd": utf16pw}
        if spn is not None:
            details["servicePrincipalName"] = spn
        if upn is not None:
            details["userPrincipalName"] = upn
        self.ldb.add(details)

        creds = Credentials()
        creds.guess(self.lp)
        creds.set_realm(self.ldb.domain_dns_name().upper())
        creds.set_domain(self.ldb.domain_netbios_name().upper())
        creds.set_password(password)
        creds.set_username(account_name)
        if machine_account:
            creds.set_workstation(name)
        #
        # Save the account name so it can be deleted in the tearDown
        self.accounts.append(dn)

        return (creds, dn)

    def as_req(self, cname, sname, realm, etypes, padata=None):
        '''Send a Kerberos AS_REQ, returns the undecoded response
        '''

        till = self.get_KerberosTime(offset=36000)
        kdc_options = 0

        req = self.AS_REQ_create(padata=padata,
                                 kdc_options=str(kdc_options),
                                 cname=cname,
                                 realm=realm,
                                 sname=sname,
                                 from_time=None,
                                 till_time=till,
                                 renew_time=None,
                                 nonce=0x7fffffff,
                                 etypes=etypes,
                                 addresses=None,
                                 EncAuthorizationData=None,
                                 EncAuthorizationData_key=None,
                                 additional_tickets=None)
        rep = self.send_recv_transaction(req)
        return rep

    def get_as_rep_key(self, creds, rep):
        '''Extract the session key from an AS-REP
        '''
        rep_padata = self.der_decode(
            rep['e-data'],
            asn1Spec=krb5_asn1.METHOD_DATA())

        for pa in rep_padata:
            if pa['padata-type'] == PADATA_ETYPE_INFO2:
                padata_value = pa['padata-value']
                break

        etype_info2 = self.der_decode(
            padata_value, asn1Spec=krb5_asn1.ETYPE_INFO2())

        key = self.PasswordKey_from_etype_info2(creds, etype_info2[0])
        return key

    def get_pa_data(self, creds, rep, skew=0):
        '''generate the pa_data data element for an AS-REQ
        '''
        key = self.get_as_rep_key(creds, rep)

        (patime, pausec) = self.get_KerberosTimeWithUsec(offset=skew)
        padata = self.PA_ENC_TS_ENC_create(patime, pausec)
        padata = self.der_encode(padata, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        padata = self.EncryptedData_create(key, KU_PA_ENC_TIMESTAMP, padata)
        padata = self.der_encode(padata, asn1Spec=krb5_asn1.EncryptedData())

        padata = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, padata)

        return [padata]

    def get_as_rep_enc_data(self, key, rep):
        ''' Decrypt and Decode the encrypted data in an AS-REP
        '''
        enc_part = key.decrypt(KU_AS_REP_ENC_PART, rep['enc-part']['cipher'])
        # MIT KDC encodes both EncASRepPart and EncTGSRepPart with
        # application tag 26
        try:
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncASRepPart())
        except Exception:
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncTGSRepPart())

        return enc_part

    def check_pre_authenication(self, rep):
        """ Check that the kdc response was pre-authentication required
        """
        self.check_error_rep(rep, KDC_ERR_PREAUTH_REQUIRED)

    def check_as_reply(self, rep):
        """ Check that the kdc response is an AS-REP and that the
            values for:
                msg-type
                pvno
                tkt-pvno
                kvno
            match the expected values
        """

        # Should have a reply, and it should an AS-REP message.
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_AS_REP, "rep = {%s}" % rep)

        # Protocol version number should be 5
        pvno = int(rep['pvno'])
        self.assertEqual(5, pvno, "rep = {%s}" % rep)

        # The ticket version number should be 5
        tkt_vno = int(rep['ticket']['tkt-vno'])
        self.assertEqual(5, tkt_vno, "rep = {%s}" % rep)

        # Check that the kvno is not an RODC kvno
        # MIT kerberos does not provide the kvno, so we treat it as optional.
        # This is tested in compatability_test.py
        if 'kvno' in rep['enc-part']:
            kvno = int(rep['enc-part']['kvno'])
            # If the high order bits are set this is an RODC kvno.
            self.assertEqual(0, kvno & 0xFFFF0000, "rep = {%s}" % rep)

    def check_tgs_reply(self, rep):
        """ Check that the kdc response is an TGS-REP and that the
            values for:
                msg-type
                pvno
                tkt-pvno
                kvno
            match the expected values
        """

        # Should have a reply, and it should an TGS-REP message.
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_TGS_REP, "rep = {%s}" % rep)

        # Protocol version number should be 5
        pvno = int(rep['pvno'])
        self.assertEqual(5, pvno, "rep = {%s}" % rep)

        # The ticket version number should be 5
        tkt_vno = int(rep['ticket']['tkt-vno'])
        self.assertEqual(5, tkt_vno, "rep = {%s}" % rep)

        # Check that the kvno is not an RODC kvno
        # MIT kerberos does not provide the kvno, so we treat it as optional.
        # This is tested in compatability_test.py
        if 'kvno' in rep['enc-part']:
            kvno = int(rep['enc-part']['kvno'])
            # If the high order bits are set this is an RODC kvno.
            self.assertEqual(0, kvno & 0xFFFF0000, "rep = {%s}" % rep)

    def check_error_rep(self, rep, expected):
        """ Check that the reply is an error message, with the expected
            error-code specified.
        """
        self.assertIsNotNone(rep)
        self.assertEqual(rep['msg-type'], KRB_ERROR, "rep = {%s}" % rep)
        self.assertEqual(rep['error-code'], expected, "rep = {%s}" % rep)

    def tgs_req(self, cname, sname, realm, ticket, key, etypes):
        '''Send a TGS-REQ, returns the response and the decrypted and
           decoded enc-part
        '''

        kdc_options = "0"
        till = self.get_KerberosTime(offset=36000)
        padata = []

        subkey = self.RandomKey(key.etype)

        (ctime, cusec) = self.get_KerberosTimeWithUsec()

        req = self.TGS_REQ_create(padata=padata,
                                  cusec=cusec,
                                  ctime=ctime,
                                  ticket=ticket,
                                  kdc_options=str(kdc_options),
                                  cname=cname,
                                  realm=realm,
                                  sname=sname,
                                  from_time=None,
                                  till_time=till,
                                  renew_time=None,
                                  nonce=0x7ffffffe,
                                  etypes=etypes,
                                  addresses=None,
                                  EncAuthorizationData=None,
                                  EncAuthorizationData_key=None,
                                  additional_tickets=None,
                                  ticket_session_key=key,
                                  authenticator_subkey=subkey)
        rep = self.send_recv_transaction(req)
        self.assertIsNotNone(rep)

        msg_type = rep['msg-type']
        enc_part = None
        if msg_type == KRB_TGS_REP:
            enc_part = subkey.decrypt(
                KU_TGS_REP_ENC_PART_SUB_KEY, rep['enc-part']['cipher'])
            enc_part = self.der_decode(
                enc_part, asn1Spec=krb5_asn1.EncTGSRepPart())
        return (rep, enc_part)

    # Named tuple to contain values of interest when the PAC is decoded.
    PacData = namedtuple(
        "PacData",
        "account_name account_sid logon_name upn domain_name")
    PAC_LOGON_INFO = 1
    PAC_CREDENTIAL_INFO = 2
    PAC_SRV_CHECKSUM = 6
    PAC_KDC_CHECKSUM = 7
    PAC_LOGON_NAME = 10
    PAC_CONSTRAINED_DELEGATION = 11
    PAC_UPN_DNS_INFO = 12

    def get_pac_data(self, authorization_data):
        '''Decode the PAC element contained in the authorization-data element
        '''
        account_name = None
        user_sid = None
        logon_name = None
        upn = None
        domain_name = None

        # The PAC data will be wrapped in an AD_IF_RELEVANT element
        ad_if_relevant_elements = (
            x for x in authorization_data if x['ad-type'] == AD_IF_RELEVANT)
        for dt in ad_if_relevant_elements:
            buf = self.der_decode(
                dt['ad-data'], asn1Spec=krb5_asn1.AD_IF_RELEVANT())
            # The PAC data is further wrapped in a AD_WIN2K_PAC element
            for ad in (x for x in buf if x['ad-type'] == AD_WIN2K_PAC):
                pb = ndr_unpack(krb5pac.PAC_DATA, ad['ad-data'])
                for pac in pb.buffers:
                    if pac.type == self.PAC_LOGON_INFO:
                        account_name = (
                            pac.info.info.info3.base.account_name)
                        user_sid = (
                            str(pac.info.info.info3.base.domain_sid)
                            + "-" + str(pac.info.info.info3.base.rid))
                    elif pac.type == self.PAC_LOGON_NAME:
                        logon_name = pac.info.account_name
                    elif pac.type == self.PAC_UPN_DNS_INFO:
                        upn = pac.info.upn_name
                        domain_name = pac.info.dns_domain_name

        return self.PacData(
            account_name,
            user_sid,
            logon_name,
            upn,
            domain_name)

    def decode_service_ticket(self, creds, ticket):
        '''Decrypt and decode a service ticket
        '''

        name = creds.get_username()
        if name.endswith('$'):
            name = name[:-1]
        realm = creds.get_realm()
        salt = "%s.%s@%s" % (name, realm.lower(), realm.upper())

        key = self.PasswordKey_create(
            ticket['enc-part']['etype'],
            creds.get_password(),
            salt,
            ticket['enc-part']['kvno'])

        enc_part = key.decrypt(KU_TICKET, ticket['enc-part']['cipher'])
        enc_ticket_part = self.der_decode(
            enc_part, asn1Spec=krb5_asn1.EncTicketPart())
        return enc_ticket_part

    def get_objectSid(self, dn):
        ''' Get the objectSID for a DN
            Note: performs an Ldb query.
        '''
        res = self.ldb.search(dn, scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res) == 1, "did not get objectSid for %s" % dn)
        sid = self.ldb.schema_format_value("objectSID", res[0]["objectSID"][0])
        return sid.decode('utf8')

    def add_attribute(self, dn_str, name, value):
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        flag = ldb.FLAG_MOD_ADD

        dn = ldb.Dn(self.ldb, dn_str)
        msg = ldb.Message(dn)
        msg[name] = ldb.MessageElement(values, flag, name)
        self.ldb.modify(msg)

    def modify_attribute(self, dn_str, name, value):
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        flag = ldb.FLAG_MOD_REPLACE

        dn = ldb.Dn(self.ldb, dn_str)
        msg = ldb.Message(dn)
        msg[name] = ldb.MessageElement(values, flag, name)
        self.ldb.modify(msg)

    def create_ccache(self, cname, ticket, enc_part):
        """ Lay out a version 4 on-disk credentials cache, to be read using the
            FILE: protocol.
        """

        field = krb5ccache.DELTATIME_TAG()
        field.kdc_sec_offset = 0
        field.kdc_usec_offset = 0

        v4tag = krb5ccache.V4TAG()
        v4tag.tag = 1
        v4tag.field = field

        v4tags = krb5ccache.V4TAGS()
        v4tags.tag = v4tag
        v4tags.further_tags = b''

        optional_header = krb5ccache.V4HEADER()
        optional_header.v4tags = v4tags

        cname_string = cname['name-string']

        cprincipal = krb5ccache.PRINCIPAL()
        cprincipal.name_type = cname['name-type']
        cprincipal.component_count = len(cname_string)
        cprincipal.realm = ticket['realm']
        cprincipal.components = cname_string

        sname = ticket['sname']
        sname_string = sname['name-string']

        sprincipal = krb5ccache.PRINCIPAL()
        sprincipal.name_type = sname['name-type']
        sprincipal.component_count = len(sname_string)
        sprincipal.realm = ticket['realm']
        sprincipal.components = sname_string

        key = self.EncryptionKey_import(enc_part['key'])

        key_data = key.export_obj()
        keyblock = krb5ccache.KEYBLOCK()
        keyblock.enctype = key_data['keytype']
        keyblock.data = key_data['keyvalue']

        addresses = krb5ccache.ADDRESSES()
        addresses.count = 0
        addresses.data = []

        authdata = krb5ccache.AUTHDATA()
        authdata.count = 0
        authdata.data = []

        # Re-encode the ticket, since it was decoded by another layer.
        ticket_data = self.der_encode(ticket, asn1Spec=krb5_asn1.Ticket())

        authtime = enc_part['authtime']
        try:
            starttime = enc_part['starttime']
        except KeyError:
            starttime = authtime
        endtime = enc_part['endtime']

        cred = krb5ccache.CREDENTIAL()
        cred.client = cprincipal
        cred.server = sprincipal
        cred.keyblock = keyblock
        cred.authtime = int(datetime.strptime(authtime.decode(),
                                              "%Y%m%d%H%M%SZ").timestamp())
        cred.starttime = int(datetime.strptime(starttime.decode(),
                                               "%Y%m%d%H%M%SZ").timestamp())
        cred.endtime = int(datetime.strptime(endtime.decode(),
                                             "%Y%m%d%H%M%SZ").timestamp())
        cred.renew_till = cred.endtime
        cred.is_skey = 0
        cred.ticket_flags = int(enc_part['flags'], 2)
        cred.addresses = addresses
        cred.authdata = authdata
        cred.ticket = ticket_data
        cred.second_ticket = b''

        ccache = krb5ccache.CCACHE()
        ccache.pvno = 5
        ccache.version = 4
        ccache.optional_header = optional_header
        ccache.principal = cprincipal
        ccache.cred = cred

        # Serialise the credentials cache structure.
        result = ndr_pack(ccache)

        # Create a temporary file and write the credentials.
        cachefile = tempfile.NamedTemporaryFile(dir=self.tempdir, delete=False)
        cachefile.write(result)
        cachefile.close()

        return cachefile

    def create_ccache_with_user(self, user_credentials, mach_name,
                                service="host"):
        # Obtain a service ticket authorising the user and place it into a
        # newly created credentials cache file.

        user_name = user_credentials.get_username()
        realm = user_credentials.get_realm()

        # Do the initial AS-REQ, should get a pre-authentication required
        # response
        etype = (AES256_CTS_HMAC_SHA1_96, ARCFOUR_HMAC_MD5)
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])
        sname = self.PrincipalName_create(name_type=NT_SRV_HST,
                                          names=["krbtgt", realm])

        rep = self.as_req(cname, sname, realm, etype)
        self.check_pre_authenication(rep)

        # Do the next AS-REQ
        padata = self.get_pa_data(user_credentials, rep)
        key = self.get_as_rep_key(user_credentials, rep)
        rep = self.as_req(cname, sname, realm, etype, padata=padata)
        self.check_as_reply(rep)

        # Request a ticket to the host service on the machine account
        ticket = rep['ticket']
        enc_part = self.get_as_rep_enc_data(key, rep)
        key = self.EncryptionKey_import(enc_part['key'])
        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[user_name])
        sname = self.PrincipalName_create(name_type=NT_SRV_HST,
                                          names=[service, mach_name])

        (rep, enc_part) = self.tgs_req(
            cname, sname, realm, ticket, key, etype)
        self.check_tgs_reply(rep)
        key = self.EncryptionKey_import(enc_part['key'])

        # Check the contents of the pac, and the ticket
        ticket = rep['ticket']

        # Write the ticket into a credentials cache file that can be ingested
        # by the main credentials code.
        cachefile = self.create_ccache(cname, ticket, enc_part)

        # Create a credentials object to reference the credentials cache.
        creds = Credentials()
        creds.set_kerberos_state(MUST_USE_KERBEROS)
        creds.set_username(user_name, SPECIFIED)
        creds.set_realm(realm)
        creds.set_named_ccache(cachefile.name, SPECIFIED, self.lp)

        # Return the credentials along with the cache file.
        return (creds, cachefile)
