#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) Catalyst.Net Ltd 2024
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

from typing import Iterable, NewType, Optional, Tuple, TypeVar

import datetime
from itertools import chain

import ldb

from samba import auth, dsdb, gensec, werror
from samba.dcerpc import gkdi, gmsa, misc, netlogon, security
from samba.ndr import ndr_pack, ndr_unpack
from samba.nt_time import (
    nt_time_delta_from_timedelta,
    nt_time_from_datetime,
    NtTime,
    NtTimeDelta,
    timedelta_from_nt_time_delta,
)
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.gkdi import (
    Gkid,
    GroupKey,
    KEY_CYCLE_DURATION,
    MAX_CLOCK_SKEW,
)

from samba.tests import connect_samdb
from samba.tests.krb5 import kcrypto
from samba.tests.gkdi import GkdiBaseTest, ROOT_KEY_START_TIME
from samba.tests.krb5.kdc_base_test import KDCBaseTest
from samba.tests.krb5.raw_testcase import KerberosCredentials
from samba.tests.krb5.rfc4120_constants import (
    KU_PA_ENC_TIMESTAMP,
    NT_PRINCIPAL,
    PADATA_ENC_TIMESTAMP,
)
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

GMSA_DEFAULT_MANAGED_PASSWORD_INTERVAL = 30

Gmsa = NewType("Gmsa", ldb.Message)


def gkdi_rollover_interval(managed_password_interval: int) -> NtTimeDelta:
    rollover_interval = NtTimeDelta(
        managed_password_interval * 24 // 10 * KEY_CYCLE_DURATION
    )
    if rollover_interval == 0:
        raise ValueError("rollover interval must not be zero")
    return rollover_interval


class GmsaSeries:
    start_time: NtTime
    rollover_interval: NtTimeDelta

    def __init__(self, start_gkid: Gkid, rollover_interval: NtTimeDelta) -> None:
        self.start_time = start_gkid.start_nt_time()
        self.rollover_interval = rollover_interval

    def interval_gkid(self, n: int) -> Gkid:
        return Gkid.from_nt_time(self.start_of_interval(n))

    def start_of_interval(self, n: int) -> NtTime:
        if not isinstance(n, int):
            raise ValueError(f"{n} must be an integer")
        return NtTime(int(self.start_time + n * self.rollover_interval))

    def during_interval(self, n: int) -> NtTime:
        return NtTime(int(self.start_of_interval(n) + self.rollover_interval // 2))

    def during_skew_window(self, n: int) -> NtTime:
        two_minutes = nt_time_delta_from_timedelta(datetime.timedelta(minutes=2))
        return NtTime(
            int(self.start_of_interval(n) + self.rollover_interval - two_minutes)
        )


class GmsaTests(GkdiBaseTest, KDCBaseTest):
    def _as_req(
        self,
        creds: KerberosCredentials,
        target_creds: KerberosCredentials,
        enctype: kcrypto.Enctype,
    ) -> dict:
        preauth_key = self.PasswordKey_from_creds(creds, enctype)

        def generate_padata_fn(
            _kdc_exchange_dict: dict, _callback_dict: Optional[dict], req_body: dict
        ) -> Tuple[list, dict]:
            padata = []

            patime, pausec = self.get_KerberosTimeWithUsec()
            enc_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
            enc_ts = self.der_encode(enc_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

            enc_ts = self.EncryptedData_create(preauth_key, KU_PA_ENC_TIMESTAMP, enc_ts)
            enc_ts = self.der_encode(enc_ts, asn1Spec=krb5_asn1.EncryptedData())

            enc_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, enc_ts)

            padata.append(enc_ts)

            return padata, req_body

        user_name = creds.get_username()
        cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=user_name.split("/")
        )

        target_name = target_creds.get_username()
        target_realm = target_creds.get_realm()

        sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=["host", target_name[:-1]]
        )

        check_error_fn = None
        check_rep_fn = self.generic_check_kdc_rep

        expected_sname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL, names=[target_name]
        )

        kdc_options = "forwardable,renewable,canonicalize,renewable-ok"
        kdc_options = krb5_asn1.KDCOptions(kdc_options)

        ticket_decryption_key = self.TicketDecryptionKey_from_creds(target_creds)

        kdc_exchange_dict = self.as_exchange_dict(
            creds=creds,
            expected_crealm=creds.get_realm(),
            expected_cname=cname,
            expected_srealm=target_realm,
            expected_sname=expected_sname,
            expected_supported_etypes=target_creds.tgs_supported_enctypes,
            ticket_decryption_key=ticket_decryption_key,
            generate_padata_fn=generate_padata_fn,
            check_error_fn=check_error_fn,
            check_rep_fn=check_rep_fn,
            check_kdc_private_fn=self.generic_check_kdc_private,
            expected_error_mode=0,
            expected_salt=creds.get_salt(),
            preauth_key=preauth_key,
            kdc_options=str(kdc_options),
        )

        till = self.get_KerberosTime(offset=36000)

        etypes = kcrypto.Enctype.AES256, kcrypto.Enctype.RC4

        rep = self._generic_kdc_exchange(
            kdc_exchange_dict,
            cname=cname,
            realm=target_realm,
            sname=sname,
            till_time=till,
            etypes=etypes,
        )
        self.check_as_reply(rep)

        return kdc_exchange_dict

    # Note: unused
    def gkdi_get_key_start_time(self, key_id: gkdi.KeyEnvelope) -> NtTime:
        return Gkid.from_key_envelope(key_id).start_nt_time()

    def get_password(
        self,
        samdb: SamDB,
        target_sd: bytes,
        root_key_id: Optional[misc.GUID],
        gkid: Gkid,
        sid: security.dom_sid,
    ) -> bytes:
        group_key = self.get_key_exact(samdb, target_sd, root_key_id, gkid)

        password = self.generate_gmsa_password(group_key, sid)
        return self.post_process_password_buffer(password)

    def get_password_based_on_gkid(
        self, samdb: SamDB, gkid: Gkid, sid: security.dom_sid
    ) -> bytes:
        return self.get_password(samdb, self.gmsa_sd, None, gkid, sid)

    def get_password_based_on_timestamp(
        self, samdb: SamDB, timestamp: NtTime, sid: security.dom_sid
    ) -> bytes:
        return self.get_password_based_on_gkid(samdb, Gkid.from_nt_time(timestamp), sid)

    # Note: unused
    def get_password_based_on_key_id(
        self, samdb: SamDB, managed_password: gkdi.KeyEnvelope, sid: str
    ) -> bytes:
        return self.get_password(
            samdb,
            self.gmsa_sd,
            managed_password.root_key_id,
            Gkid.from_key_envelope(managed_password),
            sid,
        )

    def generate_gmsa_password(self, key: GroupKey, sid: str) -> bytes:
        context = ndr_pack(security.dom_sid(sid))
        algorithm = key.hash_algorithm.algorithm()
        gmsa_password_len = 256

        return self.kdf(
            algorithm,
            key.key,
            context,
            label="GMSA PASSWORD",
            len_in_bytes=gmsa_password_len,
        )

    def post_process_password_buffer(self, key: bytes) -> bytes:
        self.assertEqual(0, len(key) & 1, f"length of key ({len(key)}) is not even")

        def convert_null(t: Tuple[int, int]) -> Tuple[int, int]:
            if t == (0, 0):
                return 1, 0

            return t

        T = TypeVar("T")

        def take_pairs(iterable: Iterable[T]) -> Iterable[Tuple[T, T]]:
            it = iter(iterable)
            while True:
                try:
                    first = next(it)
                except StopIteration:
                    break

                yield first, next(it)

        return bytes(chain.from_iterable(map(convert_null, take_pairs(key))))

    def get_gmsa_object(self, samdb: SamDB, dn: ldb.Dn) -> Gmsa:
        res = samdb.search(
            dn,
            scope=ldb.SCOPE_BASE,
            attrs=[
                "msDS-ManagedPasswordInterval",
                "msDS-ManagedPasswordId",
                "msDS-ManagedPasswordPreviousId",
                "whenCreated",
            ],
        )
        return res[0]

    def gmsa_rollover_interval(self, gmsa_object: Gmsa) -> NtTimeDelta:
        managed_password_interval = gmsa_object.get(
            "msDS-ManagedPasswordInterval", idx=0
        )
        if managed_password_interval is None:
            managed_password_interval = GMSA_DEFAULT_MANAGED_PASSWORD_INTERVAL
        else:
            managed_password_interval = int(managed_password_interval)

        return gkdi_rollover_interval(managed_password_interval)

    def gmsa_creation_nt_time(self, gmsa_object: Gmsa) -> NtTime:
        creation_time: Optional[bytes] = gmsa_object.get("whenCreated", idx=0)
        self.assertIsNotNone(creation_time)
        assert creation_time is not None  # to help the type checker

        create_time = datetime.datetime.fromtimestamp(
            ldb.string_to_time(creation_time.decode()), tz=datetime.timezone.utc
        )
        return nt_time_from_datetime(create_time)

    def gmsa_series(self, managed_password_interval: int) -> GmsaSeries:
        return GmsaSeries(
            self.future_gkid(), gkdi_rollover_interval(managed_password_interval)
        )

    def expected_gmsa_password_blob(
        self,
        samdb: SamDB,
        creds: KerberosCredentials,
        gkid: Gkid,
        *,
        query_expiration_gkid: Gkid,
        previous_gkid: Optional[Gkid] = None,
        return_future_key: bool = False,
    ) -> gmsa.MANAGEDPASSWORD_BLOB:
        new_password = self.get_password_based_on_gkid(samdb, gkid, creds.get_sid())
        old_password = None
        if previous_gkid is not None:
            old_password = self.get_password_based_on_gkid(
                samdb, previous_gkid, creds.get_sid()
            )

        current_time = self.current_nt_time(samdb)

        gmsa_object = self.get_gmsa_object(samdb, creds.get_dn())
        gkdi_rollover_interval = self.gmsa_rollover_interval(gmsa_object)

        query_expiration_time = query_expiration_gkid.start_nt_time()
        query_password_interval = NtTimeDelta(query_expiration_time - current_time)
        unchanged_password_interval = NtTimeDelta(
            max(
                0,
                query_expiration_time
                + (gkdi_rollover_interval if return_future_key else 0)
                - current_time
                - MAX_CLOCK_SKEW,
            )
        )

        return self.marshal_password(
            new_password,
            old_password,
            query_password_interval,
            unchanged_password_interval,
        )

    def expected_current_gmsa_password_blob(
        self,
        samdb: SamDB,
        creds: KerberosCredentials,
        *,
        future_key_is_acceptable: bool,
    ) -> gmsa.MANAGEDPASSWORD_BLOB:
        gmsa_object = self.get_gmsa_object(samdb, creds.get_dn())

        gkdi_rollover_interval = self.gmsa_rollover_interval(gmsa_object)

        pwd_id_blob = gmsa_object.get("msDS-ManagedPasswordId", idx=0)
        self.assertIsNotNone(pwd_id_blob, "SAM should have initialized password ID")

        pwd_id = ndr_unpack(gkdi.KeyEnvelope, pwd_id_blob)
        key_start_time = Gkid.from_key_envelope(pwd_id).start_nt_time()

        current_time = self.current_nt_time(samdb)

        time_since_key_start = NtTimeDelta(current_time - key_start_time)
        quantized_time_since_key_start = NtTimeDelta(
            time_since_key_start // gkdi_rollover_interval * gkdi_rollover_interval
        )
        new_key_start_time = NtTime(key_start_time + quantized_time_since_key_start)
        new_key_expiration_time = NtTime(new_key_start_time + gkdi_rollover_interval)

        account_sid = creds.get_sid()

        within_clock_skew_window = (
            new_key_expiration_time - current_time <= MAX_CLOCK_SKEW
        )
        return_future_key = future_key_is_acceptable and within_clock_skew_window
        if return_future_key:
            new_password = self.get_password_based_on_timestamp(
                samdb, new_key_expiration_time, account_sid
            )
            old_password = self.get_password_based_on_timestamp(
                samdb, new_key_start_time, account_sid
            )
        else:
            new_password = self.get_password_based_on_timestamp(
                samdb, new_key_start_time, account_sid
            )

            account_age = NtTimeDelta(
                current_time - self.gmsa_creation_nt_time(gmsa_object)
            )
            if account_age >= gkdi_rollover_interval:
                old_password = self.get_password_based_on_timestamp(
                    samdb,
                    NtTime(new_key_start_time - gkdi_rollover_interval),
                    account_sid,
                )
            else:
                # The account is not old enough to have a previous password.
                old_password = None

        key_expiration_time = NtTime(key_start_time + gkdi_rollover_interval)
        key_is_expired = key_expiration_time <= current_time

        query_expiration_time = NtTime(
            new_key_expiration_time if key_is_expired else key_expiration_time
        )
        query_password_interval = NtTimeDelta(query_expiration_time - current_time)
        unchanged_password_interval = NtTimeDelta(
            max(
                0,
                query_expiration_time
                + (gkdi_rollover_interval if return_future_key else 0)
                - current_time
                - MAX_CLOCK_SKEW,
            )
        )

        return self.marshal_password(
            new_password,
            old_password,
            query_password_interval,
            unchanged_password_interval,
        )

    def marshal_password(
        self,
        current_password: bytes,
        previous_password: Optional[bytes],
        query_password_interval: NtTimeDelta,
        unchanged_password_interval: NtTimeDelta,
    ) -> gmsa.MANAGEDPASSWORD_BLOB:
        managed_password = gmsa.MANAGEDPASSWORD_BLOB()

        managed_password.passwords.current = current_password
        managed_password.passwords.previous = previous_password
        managed_password.passwords.query_interval = query_password_interval
        managed_password.passwords.unchanged_interval = unchanged_password_interval

        return managed_password

    def gmsa_account(
        self,
        *,
        samdb: Optional[SamDB] = None,
        interval: int = 1,
        msa_membership: Optional[str] = None,
        **kwargs,
    ) -> KerberosCredentials:
        if msa_membership is None:
            allow_world_sddl = "O:SYD:(A;;RP;;;WD)"
            msa_membership = allow_world_sddl

        msa_membership_sd = ndr_pack(
            security.descriptor.from_sddl(msa_membership, security.dom_sid())
        )

        try:
            creds = self.get_cached_creds(
                samdb=samdb,
                account_type=self.AccountType.GROUP_MANAGED_SERVICE,
                opts={
                    "additional_details": self.freeze(
                        {
                            "msDS-GroupMSAMembership": msa_membership_sd,
                            "msDS-ManagedPasswordInterval": str(interval),
                        }
                    ),
                    **kwargs,
                },
                # Ensure the gMSA is a brand‐new account.
                use_cache=False,
            )
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_UNWILLING_TO_PERFORM:
                self.fail(
                    "If you’re running these tests against Windows, try “warming up”"
                    " the GKDI service by running `samba.tests.krb5.gkdi_tests` first."
                )

            raise

        # Derive the account’s current password. The account is too new to have a previous password yet.
        managed_pwd = self.expected_current_gmsa_password_blob(
            self.get_samdb() if samdb is None else samdb,
            creds,
            future_key_is_acceptable=False,
        )

        # Set the password.
        self.assertIsNotNone(
            managed_pwd.passwords.current, "current password must be present"
        )
        creds.set_utf16_password(managed_pwd.passwords.current)

        return creds

    def get_local_samdb(self) -> SamDB:
        """Return a connection to the local database."""

        lp = self.get_lp()
        samdb = connect_samdb(
            samdb_url=lp.samdb_url(), lp=lp, credentials=self.get_admin_creds()
        )
        self.assertLocalSamDB(samdb)

        return samdb

    # Perform a gensec logon using NTLMSSP. As samdb is passed in as a
    # parameter, it can have a time set on it with set_db_time().
    def gensec_ntlmssp_logon(
        self, client_creds: Credentials, samdb: SamDB
    ) -> "auth.session_info":
        lp = self.get_lp()
        lp.set("server role", "active directory domain controller")

        settings = {"lp_ctx": lp, "target_hostname": lp.get("netbios name")}

        gensec_client = gensec.Security.start_client(settings)
        # Ensure that we don’t use Kerberos.
        self.assertEqual(DONT_USE_KERBEROS, client_creds.get_kerberos_state())
        gensec_client.set_credentials(client_creds)
        gensec_client.want_feature(gensec.FEATURE_SEAL)
        gensec_client.start_mech_by_name("ntlmssp")

        auth_context = auth.AuthContext(lp_ctx=lp, ldb=samdb)

        gensec_server = gensec.Security.start_server(settings, auth_context)
        machine_creds = Credentials()
        machine_creds.guess(lp)
        machine_creds.set_machine_account(lp)
        gensec_server.set_credentials(machine_creds)

        gensec_server.start_mech_by_name("ntlmssp")

        client_finished = False
        server_finished = False
        client_to_server = b""
        server_to_client = b""

        # Operate as both the client and the server to verify the user’s credentials.
        while not client_finished or not server_finished:
            if not client_finished:
                client_finished, client_to_server = gensec_client.update(
                    server_to_client
                )
            if not server_finished:
                server_finished, server_to_client = gensec_server.update(
                    client_to_server
                )

        # Retrieve the SIDs from the security token.
        return gensec_server.session_info()

    def check_nt_interval(
        self,
        expected_nt_interval: NtTimeDelta,
        nt_interval: NtTimeDelta,
        interval_name: str,
    ) -> None:
        """Check that the intervals match to within thirty seconds or so."""

        threshold = datetime.timedelta(seconds=30)

        interval = timedelta_from_nt_time_delta(nt_interval)
        expected_interval = timedelta_from_nt_time_delta(expected_nt_interval)
        interval_difference = abs(interval - expected_interval)
        self.assertLess(
            interval_difference,
            threshold,
            f"{interval_name} ({interval}) is out by {interval_difference} from"
            f" expected ({expected_interval})",
        )

    def check_managed_pwd_intervals(
        self,
        expected_managed_pwd: gmsa.MANAGEDPASSWORD_BLOB,
        managed_pwd: gmsa.MANAGEDPASSWORD_BLOB,
    ) -> None:
        expected_passwords = expected_managed_pwd.passwords
        passwords = managed_pwd.passwords

        self.check_nt_interval(
            expected_passwords.query_interval,
            passwords.query_interval,
            "query interval",
        )
        self.check_nt_interval(
            expected_passwords.unchanged_interval,
            passwords.unchanged_interval,
            "unchanged interval",
        )

    def check_managed_pwd(
        self,
        samdb: SamDB,
        creds: KerberosCredentials,
        *,
        expected_managed_pwd: gmsa.MANAGEDPASSWORD_BLOB,
    ) -> None:
        res = samdb.search(
            creds.get_dn(), scope=ldb.SCOPE_BASE, attrs=["msDS-ManagedPassword"]
        )
        self.assertEqual(1, len(res), "gMSA not found")
        managed_password = res[0].get("msDS-ManagedPassword", idx=0)

        self.assertIsNotNone(managed_password)
        managed_pwd = ndr_unpack(gmsa.MANAGEDPASSWORD_BLOB, managed_password)

        self.assertEqual(1, managed_pwd.version)
        self.assertEqual(0, managed_pwd.reserved)
        self.assertEqual(len(managed_password), managed_pwd.length)

        self.assertIsNotNone(expected_managed_pwd.passwords.current)

        self.assertEqual(
            managed_pwd.passwords.current, expected_managed_pwd.passwords.current
        )
        self.assertEqual(
            managed_pwd.passwords.previous, expected_managed_pwd.passwords.previous
        )

        self.check_managed_pwd_intervals(expected_managed_pwd, managed_pwd)

    # When creating a gMSA, Windows seems to pick the root key with the
    # greatest msKds-CreateTime having msKds-UseStartTime ≤ ten hours ago.
    # Bear in mind that it seems also to cache the key, so it won’t always
    # use the latest one.

    def get_managed_service_accounts_dn(self) -> ldb.Dn:
        samdb = self.get_samdb()
        return samdb.get_wellknown_dn(
            samdb.get_default_basedn(), dsdb.DS_GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER
        )

    def check_managed_password_access(
        self,
        creds: Credentials,
        *,
        samdb: Optional[SamDB] = None,
        expect_access: bool = False,
        expected_werror: int = werror.WERR_SUCCESS,
    ) -> None:
        if samdb is None:
            samdb = self.get_samdb()
        if expected_werror:
            self.assertFalse(expect_access)
        managed_service_accounts_dn = self.get_managed_service_accounts_dn()
        username = creds.get_username()

        # Try base, subtree, and one‐level searches.
        searches = (
            (creds.get_dn(), ldb.SCOPE_BASE),
            (managed_service_accounts_dn, ldb.SCOPE_SUBTREE),
            (managed_service_accounts_dn, ldb.SCOPE_ONELEVEL),
        )

        for dn, scope in searches:
            # Perform a search and see whether we’re allowed to view the managed password.

            try:
                res = samdb.search(
                    dn,
                    scope=scope,
                    expression=f"sAMAccountName={username}",
                    attrs=["msDS-ManagedPassword"],
                )
            except ldb.LdbError as err:
                self.assertTrue(expected_werror, "got an unexpected error")

                num, estr = err.args
                if num != ldb.ERR_OPERATIONS_ERROR:
                    raise

                self.assertIn(f"{expected_werror:08X}", estr)
                return

            self.assertFalse(expected_werror, "expected to get an error")
            self.assertEqual(1, len(res), "should always find the gMSA")

            managed_password = res[0].get("msDS-ManagedPassword", idx=0)
            if expect_access:
                self.assertIsNotNone(
                    managed_password, "should be allowed to view the password"
                )
            else:
                self.assertIsNone(
                    managed_password, "should not be allowed to view the password"
                )

    def test_retrieved_password_allowed(self):
        """Test being allowed to view the managed password."""
        self.check_managed_password_access(self.gmsa_account(), expect_access=True)

    def test_retrieved_password_denied(self):
        """Test not being allowed to view the managed password."""
        deny_world_sddl = "O:SYD:(D;;RP;;;WD)"
        self.check_managed_password_access(
            self.gmsa_account(msa_membership=deny_world_sddl), expect_access=False
        )

    def test_retrieving_denied_password_over_unsealed_connection(self):
        # Requires --use-kerberos=required, or it automatically upgrades to an
        # encrypted connection.

        # Remove FEATURE_SEAL which gets added by insta_creds.
        creds = self.insta_creds(template=self.get_admin_creds())
        creds.set_gensec_features(creds.get_gensec_features() & ~gensec.FEATURE_SEAL)

        lp = self.get_lp()

        sasl_wrap = lp.get("client ldap sasl wrapping")
        self.addCleanup(lp.set, "client ldap sasl wrapping", sasl_wrap)
        lp.set("client ldap sasl wrapping", "sign")

        # Create a second ldb connection without seal.
        samdb = SamDB(
            f"ldap://{self.dc_host}",
            credentials=creds,
            session_info=auth.system_session(lp),
            lp=lp,
        )

        # Deny anyone from being able to view the password.
        deny_world_sddl = "O:SYD:(D;;RP;;;WD)"
        self.check_managed_password_access(
            self.gmsa_account(msa_membership=deny_world_sddl),
            samdb=samdb,
            expected_werror=werror.WERR_DS_CONFIDENTIALITY_REQUIRED,
        )

    def future_gkid(self) -> Gkid:
        """Return (6333, 26, 5)—an arbitrary GKID far enough in the future that
        it’s situated beyond any reasonable rollover period. But not so far in
        the future that Python’s datetime library will throw OverflowErrors."""
        future_date = datetime.datetime(9000, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
        return Gkid.from_nt_time(nt_time_from_datetime(future_date))

    def future_time(self) -> NtTime:
        """Return an arbitrary time far enough in the future that it’s situated
        beyond any reasonable rollover period. But not so far in the future that
        Python’s datetime library will throw OverflowErrors."""
        return self.future_gkid().start_nt_time()

    def test_retrieved_password(self):
        """Test that we can retrieve the correct password for a gMSA."""

        samdb = self.get_samdb()
        creds = self.gmsa_account()

        expected = self.expected_current_gmsa_password_blob(
            samdb,
            creds,
            future_key_is_acceptable=True,
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_when_current_key_is_valid(self):
        """Test that we can retrieve the correct password for a gMSA at a time
        when we are sure it is valid."""
        password_interval = 37

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        # Check the managed password of the account the moment it has been
        # created.
        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(0),
            previous_gkid=series.interval_gkid(-1),
            query_expiration_gkid=series.interval_gkid(1),
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_when_current_key_is_expired(self):
        """Test that we can retrieve the correct password for a gMSA when the
        original password has expired."""
        password_interval = 14

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        # Set the time to the moment the original password has expired, and
        # check that the managed password is correct.
        expired_time = series.start_of_interval(1)
        self.set_db_time(samdb, expired_time)
        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(1),
            previous_gkid=series.interval_gkid(0),
            query_expiration_gkid=series.interval_gkid(2),
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_when_next_key_is_expired(self):
        password_interval = 1

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        expired_time = series.start_of_interval(2)
        self.set_db_time(samdb, expired_time)

        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(2),
            previous_gkid=series.interval_gkid(1),
            query_expiration_gkid=series.interval_gkid(3),
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_during_clock_skew_window_when_current_key_is_valid(
        self,
    ):
        password_interval = 60

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        self.set_db_time(samdb, series.during_skew_window(0))

        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(1),
            previous_gkid=series.interval_gkid(0),
            query_expiration_gkid=series.interval_gkid(1),
            return_future_key=True,
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_during_clock_skew_window_when_current_key_is_expired(
        self,
    ):
        password_interval = 100

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        self.set_db_time(samdb, series.during_skew_window(1))

        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(2),
            previous_gkid=series.interval_gkid(1),
            query_expiration_gkid=series.interval_gkid(2),
            return_future_key=True,
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieved_password_during_clock_skew_window_when_next_key_is_expired(
        self,
    ):
        password_interval = 16

        samdb = self.get_local_samdb()
        series = self.gmsa_series(password_interval)
        self.set_db_time(samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=samdb, interval=password_interval)

        self.set_db_time(samdb, series.during_skew_window(2))

        expected = self.expected_gmsa_password_blob(
            samdb,
            creds,
            series.interval_gkid(3),
            previous_gkid=series.interval_gkid(2),
            query_expiration_gkid=series.interval_gkid(3),
            return_future_key=True,
        )
        self.check_managed_pwd(samdb, creds, expected_managed_pwd=expected)

    def test_retrieving_managed_password_triggers_keys_update(self):
        # Create a root key with a start time early enough to be usable at the
        # time the gMSA is purported to be created.
        samdb = self.get_samdb()
        domain_dn = self.get_server_dn(samdb)
        self.create_root_key(samdb, domain_dn, use_start_time=ROOT_KEY_START_TIME)

        password_interval = 16

        local_samdb = self.get_local_samdb()
        series = GmsaSeries(Gkid(100, 0, 0), gkdi_rollover_interval(password_interval))
        self.set_db_time(local_samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=local_samdb, interval=password_interval)
        dn = creds.get_dn()

        current_nt_time = self.current_nt_time(local_samdb)
        self.set_db_time(local_samdb, current_nt_time)

        # Search the local database for the account’s keys.
        res = local_samdb.search(
            dn, scope=ldb.SCOPE_BASE, attrs=["unicodePwd", "supplementalCredentials"]
        )
        self.assertEqual(1, len(res))

        previous_nt_hash = res[0].get("unicodePwd", idx=0)
        previous_supplemental_creds = self.unpack_supplemental_credentials(
            res[0].get("supplementalCredentials", idx=0)
        )

        # Check that the NT hash is the value we expect.
        self.assertEqual(creds.get_nt_hash(), previous_nt_hash)

        # Search for the managed password over LDAP, triggering an update of the
        # keys in the database.
        res = samdb.search(dn, scope=ldb.SCOPE_BASE, attrs=["msDS-ManagedPassword"])
        self.assertEqual(1, len(res))

        # Verify that the password is present in the result.
        managed_password = res[0].get("msDS-ManagedPassword", idx=0)
        self.assertIsNotNone(managed_password, "should be allowed to view the password")

        # Search the local database again for the account’s keys, which should
        # have been updated.
        res = local_samdb.search(
            dn, scope=ldb.SCOPE_BASE, attrs=["unicodePwd", "supplementalCredentials"]
        )
        self.assertEqual(1, len(res))

        nt_hash = res[0].get("unicodePwd", idx=0)
        supplemental_creds = self.unpack_supplemental_credentials(
            res[0].get("supplementalCredentials", idx=0)
        )

        self.assertNotEqual(
            previous_nt_hash, nt_hash, "NT hash has not been updated (yet)"
        )
        self.assertNotEqual(
            previous_supplemental_creds,
            supplemental_creds,
            "supplementalCredentials has not been updated (yet)",
        )

        # Set the new password.
        managed_pwd = ndr_unpack(gmsa.MANAGEDPASSWORD_BLOB, managed_password)
        self.assertIsNotNone(
            managed_pwd.passwords.current, "current password must be present"
        )
        creds.set_utf16_password(managed_pwd.passwords.current)

        # Check that the new NT hash is the value we expect.
        self.assertEqual(creds.get_nt_hash(), nt_hash)

    def test_authentication_triggers_keys_update(self):
        # Create a root key with a start time early enough to be usable at the
        # time the gMSA is purported to be created. But don’t create it on a
        # local samdb with a specifically set time, because (if the key isn’t
        # deleted later) we could end up with multiple keys with identical
        # creation and start times, and tests failing when the test and the
        # server don’t agree on which root key to use at a specific time.
        samdb = self.get_samdb()
        domain_dn = self.get_server_dn(samdb)
        self.create_root_key(samdb, domain_dn, use_start_time=ROOT_KEY_START_TIME)

        password_interval = 16

        local_samdb = self.get_local_samdb()
        series = GmsaSeries(Gkid(100, 0, 0), gkdi_rollover_interval(password_interval))
        self.set_db_time(local_samdb, series.start_of_interval(0))

        creds = self.gmsa_account(samdb=local_samdb, interval=password_interval)
        dn = creds.get_dn()

        current_nt_time = self.current_nt_time(local_samdb)
        self.set_db_time(local_samdb, current_nt_time)

        # Search the local database for the account’s keys.
        res = local_samdb.search(
            dn, scope=ldb.SCOPE_BASE, attrs=["unicodePwd", "supplementalCredentials"]
        )
        self.assertEqual(1, len(res))

        previous_nt_hash = res[0].get("unicodePwd", idx=0)
        previous_supplemental_creds = self.unpack_supplemental_credentials(
            res[0].get("supplementalCredentials", idx=0)
        )

        # Check that the NT hash is the value we expect.
        self.assertEqual(creds.get_nt_hash(), previous_nt_hash)

        # Calculate the password with which to authenticate.
        managed_pwd = self.expected_current_gmsa_password_blob(
            samdb, creds, future_key_is_acceptable=False
        )

        # Set the new password.
        self.assertIsNotNone(
            managed_pwd.passwords.current, "current password must be present"
        )
        creds.set_utf16_password(managed_pwd.passwords.current)

        # Perform an authentication using the new password. The KDC should
        # recognize that the keys in the database are out of date and update
        # them.
        self._as_req(creds, self.get_service_creds(), kcrypto.Enctype.AES256)

        # Search the local database again for the account’s keys, which should
        # have been updated.
        res = local_samdb.search(
            dn, scope=ldb.SCOPE_BASE, attrs=["unicodePwd", "supplementalCredentials"]
        )
        self.assertEqual(1, len(res))

        nt_hash = res[0].get("unicodePwd", idx=0)
        supplemental_creds = self.unpack_supplemental_credentials(
            res[0].get("supplementalCredentials", idx=0)
        )

        self.assertNotEqual(
            previous_nt_hash, nt_hash, "NT hash has not been updated (yet)"
        )
        self.assertNotEqual(
            previous_supplemental_creds,
            supplemental_creds,
            "supplementalCredentials has not been updated (yet)",
        )

        # Check that the new NT hash is the value we expect.
        self.assertEqual(creds.get_nt_hash(), nt_hash)

    def test_gmsa_can_perform_gensec_ntlmssp_logon(self):
        creds = self.gmsa_account(kerberos_enabled=False)

        # Perform a gensec logon.
        session = self.gensec_ntlmssp_logon(creds, self.get_local_samdb())

        # Ensure that the first SID contained within the security token is the gMSA’s SID.
        token = session.security_token
        token_sids = token.sids
        self.assertGreater(len(token_sids), 0)

        # Ensure that they match.
        self.assertEqual(security.dom_sid(creds.get_sid()), token_sids[0])

    def test_gmsa_can_perform_netlogon(self):
        creds = self.gmsa_account(kerberos_enabled=False)
        self._test_samlogon(
            creds,
            netlogon.NetlogonNetworkInformation,
            validation_level=netlogon.NetlogonValidationSamInfo4,
            domain_joined_mach_creds=creds,
        )

    def _gmsa_can_perform_as_req(self, *, enctype: kcrypto.Enctype) -> None:
        self._as_req(self.gmsa_account(), self.get_service_creds(), enctype)

    def test_gmsa_can_perform_as_req_with_aes256(self):
        self._gmsa_can_perform_as_req(enctype=kcrypto.Enctype.AES256)

    def test_gmsa_can_perform_as_req_with_rc4(self):
        self._gmsa_can_perform_as_req(enctype=kcrypto.Enctype.RC4)

    def _gmsa_can_authenticate_to_ldap(self, *, with_kerberos: bool) -> None:
        creds = self.gmsa_account(kerberos_enabled=with_kerberos)

        protocol = "ldap"

        # Authenticate to LDAP.
        samdb_user = SamDB(
            url=f"{protocol}://{self.dc_host}", credentials=creds, lp=self.get_lp()
        )

        # Search for the user’s token groups.
        res = samdb_user.search("", scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
        self.assertEqual(1, len(res))

        token_groups = res[0].get("tokenGroups", idx=0)
        self.assertIsNotNone(token_groups)

        # Ensure that the token SID matches.
        token_sid = ndr_unpack(security.dom_sid, token_groups)
        self.assertEqual(security.dom_sid(creds.get_sid()), token_sid)

    def test_gmsa_can_authenticate_to_ldap_with_kerberos(self):
        self._gmsa_can_authenticate_to_ldap(with_kerberos=True)

    def test_gmsa_can_authenticate_to_ldap_without_kerberos(self):
        self._gmsa_can_authenticate_to_ldap(with_kerberos=False)


if __name__ == "__main__":
    import unittest

    unittest.main()
