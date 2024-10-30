# user management
#
# common code
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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

import base64
import builtins
import binascii
import datetime
import errno
import io
import os

import ldb
from samba import credentials, nttime2float
from samba.auth import system_session
from samba.common import get_bytes, get_string
from samba.dcerpc import drsblobs, security, gmsa
from samba.ndr import ndr_unpack
from samba.netcmd import Command, CommandError
from samba.samdb import SamDB
from samba.nt_time import timedelta_from_nt_time_delta, nt_time_from_datetime
from samba.gkdi import MAX_CLOCK_SKEW

# python[3]-gpgme is abandoned since ubuntu 1804 and debian 9
# have to use python[3]-gpg instead
# The API is different, need to adapt.

def _gpgme_decrypt(encrypted_bytes):
    """
    Use python[3]-gpgme to decrypt GPG.
    """
    ctx = gpgme.Context()
    ctx.armor = True  # use ASCII-armored
    out = io.BytesIO()
    ctx.decrypt(io.BytesIO(encrypted_bytes), out)
    return out.getvalue()


def _gpg_decrypt(encrypted_bytes):
    """
    Use python[3]-gpg to decrypt GPG.
    """
    ciphertext = gpg.Data(string=encrypted_bytes)
    ctx = gpg.Context(armor=True)
    # plaintext, result, verify_result
    plaintext, _, _ = ctx.decrypt(ciphertext)
    return plaintext


gpg_decrypt = None

if not gpg_decrypt:
    try:
        import gpgme
        gpg_decrypt = _gpgme_decrypt
    except ImportError:
        pass

if not gpg_decrypt:
    try:
        import gpg
        gpg_decrypt = _gpg_decrypt
    except ImportError:
        pass

if gpg_decrypt:
    decrypt_samba_gpg_help = ("Decrypt the SambaGPG password as "
                              "cleartext source")
else:
    decrypt_samba_gpg_help = ("Decrypt the SambaGPG password not supported, "
                              "python[3]-gpgme or python[3]-gpg required")


disabled_virtual_attributes = {
}

virtual_attributes = {
    "virtualClearTextUTF8": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
    },
    "virtualClearTextUTF16": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
    },
    "virtualSambaGPG": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
    },
    "unicodePwd": {
        "flags": ldb.ATTR_FLAG_FORCE_BASE64_LDIF,
    },
    "virtualManagedPasswordQueryTime": {
    },
}


def get_crypt_value(alg, utf8pw, rounds=0):
    algs = {
        "5": {"length": 43},
        "6": {"length": 86},
    }
    if alg not in algs:
        raise ValueError(f"invalid algorithm code: {alg}"
                         f"(expected one of {','.join(algs.keys())})")

    salt = os.urandom(16)
    # The salt needs to be in [A-Za-z0-9./]
    # base64 is close enough and as we had 16
    # random bytes but only need 16 characters
    # we can ignore the possible == at the end
    # of the base64 string
    # we just need to replace '+' by '.'
    b64salt = base64.b64encode(salt)[0:16].replace(b'+', b'.').decode('utf8')
    crypt_salt = ""
    if rounds != 0:
        crypt_salt = "$%s$rounds=%s$%s$" % (alg, rounds, b64salt)
    else:
        crypt_salt = "$%s$%s$" % (alg, b64salt)

    crypt_value = crypt.crypt(utf8pw, crypt_salt)
    if crypt_value is None:
        raise NotImplementedError("crypt.crypt(%s) returned None" % (crypt_salt))
    expected_len = len(crypt_salt) + algs[alg]["length"]
    if len(crypt_value) != expected_len:
        raise NotImplementedError("crypt.crypt(%s) returned a value with length %d, expected length is %d" % (
            crypt_salt, len(crypt_value), expected_len))
    return crypt_value


try:
    import hashlib
    hashlib.sha1()
    virtual_attributes["virtualSSHA"] = {
    }
except ImportError as e:
    reason = "hashlib.sha1()"
    reason += " required"
    disabled_virtual_attributes["virtualSSHA"] = {
        "reason": reason,
    }

for (alg, attr) in [("5", "virtualCryptSHA256"), ("6", "virtualCryptSHA512")]:
    try:
        import crypt
        get_crypt_value(alg, "")
        virtual_attributes[attr] = {
        }
    except ImportError as e:
        reason = "crypt"
        reason += " required"
        disabled_virtual_attributes[attr] = {
            "reason": reason,
        }
    except NotImplementedError as e:
        reason = "modern '$%s$' salt in crypt(3) required" % (alg)
        disabled_virtual_attributes[attr] = {
            "reason": reason,
        }

# Add the wDigest virtual attributes, virtualWDigest01 to virtualWDigest29
for x in range(1, 30):
    virtual_attributes["virtualWDigest%02d" % x] = {}

# Add Kerberos virtual attributes
virtual_attributes["virtualKerberosSalt"] = {}

virtual_attributes_help = "The attributes to display (comma separated). "
virtual_attributes_help += "Possible supported virtual attributes: %s" % ", ".join(sorted(virtual_attributes.keys()))
if len(disabled_virtual_attributes) != 0:
    virtual_attributes_help += "Unsupported virtual attributes: %s" % ", ".join(sorted(disabled_virtual_attributes.keys()))


class GetPasswordCommand(Command):

    def __init__(self):
        super().__init__()
        self.lp = None

    def inject_virtual_attributes(self, samdb):
        # We use sort here in order to have a predictable processing order
        # this might not be strictly needed, but also doesn't hurt here
        for a in sorted(virtual_attributes.keys()):
            flags = ldb.ATTR_FLAG_HIDDEN | virtual_attributes[a].get("flags", 0)
            samdb.schema_attribute_add(a, flags, ldb.SYNTAX_OCTET_STRING)

    def connect_for_passwords(self, url,
                              creds=None,
                              require_ldapi=True,
                              verbose=False):

        # using anonymous here, results in no authentication
        # which means we can get system privileges via
        # the privileged ldapi socket
        anon_creds = credentials.Credentials()
        anon_creds.set_anonymous()

        if url is None and not require_ldapi:
            pass
        elif url.lower().startswith("ldapi://"):
            creds = anon_creds
            pass
        elif require_ldapi:
            raise CommandError("--url requires an ldapi:// url for this command")

        if verbose:
            self.outf.write("Connecting to '%s'\n" % url)

        samdb = SamDB(url=url, session_info=system_session(),
                      credentials=creds, lp=self.lp)

        if require_ldapi or url is None:
            try:
                #
                # Make sure we're connected as SYSTEM
                #
                res = samdb.search(base='', scope=ldb.SCOPE_BASE, attrs=["tokenGroups"])
                assert len(res) == 1
                sids = res[0].get("tokenGroups")
                assert len(sids) == 1
                sid = ndr_unpack(security.dom_sid, sids[0])
                assert str(sid) == security.SID_NT_SYSTEM
            except Exception as msg:
                raise CommandError("You need to specify an URL that gives privileges as SID_NT_SYSTEM(%s)" %
                                   (security.SID_NT_SYSTEM))

        self.inject_virtual_attributes(samdb)

        return samdb

    def get_account_attributes(self, samdb, username, basedn, filter, scope,
                               attrs, decrypt, support_pw_attrs=True):

        def get_option(opts, name):
            if not opts:
                return None
            for o in opts:
                if o.lower().startswith("%s=" % name.lower()):
                    (key, _, val) = o.partition('=')
                    return val
            return None

        def get_virtual_attr_definition(attr):
            for van in sorted(virtual_attributes.keys()):
                if van.lower() != attr.lower():
                    continue
                return virtual_attributes[van]
            return None

        formats = [
            "GeneralizedTime",
            "UnixTime",
            "TimeSpec",
        ]

        def get_virtual_format_definition(opts):
            formatname = get_option(opts, "format")
            if formatname is None:
                return None
            for fm in formats:
                if fm.lower() != formatname.lower():
                    continue
                return fm
            return None

        def parse_raw_attr(raw_attr, is_hidden=False):
            (attr, _, fullopts) = raw_attr.partition(';')
            if fullopts:
                opts = fullopts.split(';')
            else:
                opts = []
            a = {}
            a["raw_attr"] = raw_attr
            a["attr"] = attr
            a["opts"] = opts
            a["vattr"] = get_virtual_attr_definition(attr)
            a["vformat"] = get_virtual_format_definition(opts)
            a["is_hidden"] = is_hidden
            return a

        raw_attrs = attrs[:]
        has_wildcard_attr = "*" in raw_attrs
        has_virtual_attrs = False
        requested_attrs = []
        implicit_attrs = []

        for raw_attr in raw_attrs:
            a = parse_raw_attr(raw_attr)
            requested_attrs.append(a)

        search_attrs = []
        has_virtual_attrs = False
        for a in requested_attrs:
            if a["vattr"] is not None:
                has_virtual_attrs = True
                continue
            if a["vformat"] is not None:
                # also add it as implicit attr,
                # where we just do
                # search_attrs.append(a["attr"])
                # later on
                implicit_attrs.append(a)
                continue
            if a["raw_attr"] in search_attrs:
                continue
            search_attrs.append(a["raw_attr"])

        if not has_wildcard_attr:
            required_attrs = [
                "sAMAccountName",
                "userPrincipalName"
            ]
            for required_attr in required_attrs:
                a = parse_raw_attr(required_attr)
                implicit_attrs.append(a)

        if has_virtual_attrs:
            if support_pw_attrs:
                required_attrs = [
                    "supplementalCredentials",
                    "unicodePwd",
                    "msDS-ManagedPassword",
                ]
                for required_attr in required_attrs:
                    a = parse_raw_attr(required_attr, is_hidden=True)
                    implicit_attrs.append(a)

        for a in implicit_attrs:
            if a["attr"] in search_attrs:
                continue
            search_attrs.append(a["attr"])

        if scope == ldb.SCOPE_BASE:
            search_controls = ["show_deleted:1", "show_recycled:1"]
        else:
            search_controls = []
        try:
            res = samdb.search(base=basedn, expression=filter,
                               scope=scope, attrs=search_attrs,
                               controls=search_controls)
            if len(res) == 0:
                raise Exception('Unable to find user "%s"' % (username or filter))
            if len(res) > 1:
                raise Exception('Matched %u multiple users with filter "%s"' % (len(res), filter))
        except Exception as msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to get password for user '%s': %s" % (username or filter, msg))
        obj = res[0]

        calculated = {}

        sc = None
        unicodePwd = None
        if "supplementalCredentials" in obj:
            sc_blob = obj["supplementalCredentials"][0]
            sc = ndr_unpack(drsblobs.supplementalCredentialsBlob, sc_blob)
        if "unicodePwd" in obj:
            unicodePwd = obj["unicodePwd"][0]
        if "msDS-ManagedPassword" in obj:
            # unpack a GMSA managed password as if we could read the
            # hidden password attributes.
            managed_password = obj["msDS-ManagedPassword"][0]
            unpacked_managed_password = ndr_unpack(gmsa.MANAGEDPASSWORD_BLOB,
                                                   managed_password)
            calculated["OLDCLEARTEXT"] = \
                unpacked_managed_password.passwords.previous
            query_interval = unpacked_managed_password.passwords.query_interval
            calculated["GMSA:query_interval"] = \
                query_interval

            query_time_datetime = \
                timedelta_from_nt_time_delta(query_interval) + datetime.datetime.now(tz=datetime.timezone.utc)

            query_time_nttime = nt_time_from_datetime(query_time_datetime)

            calculated["GMSA:query_time"] = query_time_nttime

            # This password is useful for a keytab, but not for
            # authentication, so don't show or provide it as the new password
            # just yet
            if calculated["GMSA:query_interval"] <= MAX_CLOCK_SKEW:
                calculated["Primary:CLEARTEXT"] = \
                    unpacked_managed_password.passwords.previous
            else:
                calculated["Primary:CLEARTEXT"] = \
                    unpacked_managed_password.passwords.current

        account_name = str(obj["sAMAccountName"][0])
        if "userPrincipalName" in obj:
            account_upn = str(obj["userPrincipalName"][0])
        else:
            realm = samdb.domain_dns_name()
            account_upn = "%s@%s" % (account_name, realm.lower())

        def get_package(name, min_idx=0):
            if name in calculated:
                return calculated[name]
            if sc is None:
                return None
            if min_idx < 0:
                min_idx = len(sc.sub.packages) + min_idx
            idx = 0
            for p in sc.sub.packages:
                idx += 1
                if idx <= min_idx:
                    continue
                if name != p.name:
                    continue

                return binascii.a2b_hex(p.data)
            return None

        def get_cleartext(attr_opts):
            param = get_option(attr_opts, "previous")
            if param:
                if param != "1":
                    raise CommandError(
                        f"Invalid attribute parameter ;previous={param}, "
                        "only supported value is previous=1")
                return calculated.get("OLDCLEARTEXT")
            else:
                return get_package("Primary:CLEARTEXT")

        def get_kerberos_ctr():
            primary_krb5 = get_package("Primary:Kerberos-Newer-Keys")
            if primary_krb5 is None:
                primary_krb5 = get_package("Primary:Kerberos")
            if primary_krb5 is None:
                return (0, None)
            krb5_blob = ndr_unpack(drsblobs.package_PrimaryKerberosBlob,
                                   primary_krb5)
            return (krb5_blob.version, krb5_blob.ctr)

        aes256_key = None
        kerberos_salt = None

        (krb5_v, krb5_ctr) = get_kerberos_ctr()
        if krb5_v in [3, 4]:
            kerberos_salt = krb5_ctr.salt.string

            if krb5_ctr.keys:
                def is_aes256(k):
                    return k.keytype == 18
                aes256_key = next(builtins.filter(is_aes256, krb5_ctr.keys),
                                  None)

        if decrypt:
            #
            # Samba adds 'Primary:SambaGPG' at the end.
            # When Windows sets the password it keeps
            # 'Primary:SambaGPG' and rotates it to
            # the beginning. So we can only use the value,
            # if it is the last one.
            #
            # In order to get more protection we verify
            # the nthash of the decrypted utf16 password
            # against the stored nthash in unicodePwd if
            # available, otherwise against the first 16
            # bytes of the AES256 key.
            #
            sgv = get_package("Primary:SambaGPG", min_idx=-1)
            if sgv is not None:
                try:
                    cv = gpg_decrypt(sgv)
                    #
                    # We only use the password if it matches
                    # the current nthash stored in the unicodePwd
                    # attribute, or the current AES256 key.
                    #
                    tmp = credentials.Credentials()
                    tmp.set_anonymous()
                    tmp.set_utf16_password(cv)

                    decrypted = None
                    current_hash = None

                    if unicodePwd is not None:
                        decrypted = tmp.get_nt_hash()
                        current_hash = unicodePwd
                    elif aes256_key is not None and kerberos_salt is not None:
                        tmp.set_kerberos_salt_principal(kerberos_salt)
                        decrypted = tmp.get_kerberos_key(credentials.ENCTYPE_AES256_CTS_HMAC_SHA1_96)
                        current_hash = aes256_key.value

                    if current_hash is not None and current_hash == decrypted:
                        calculated["Primary:CLEARTEXT"] = cv

                except Exception as e:
                    if gpg_decrypt is None:
                        message = decrypt_samba_gpg_help
                    else:
                        message = str(e)
                    self.outf.write(
                        "WARNING: '%s': SambaGPG can't be decrypted "
                        "into CLEARTEXT: %s\n" % (
                            username or account_name, message))

        def get_utf8(a, b, username):
            creds_for_charcnv = credentials.Credentials()
            creds_for_charcnv.set_anonymous()
            creds_for_charcnv.set_utf16_password(get_bytes(b))

            # This can't fail due to character conversion issues as it
            # includes a built-in fallback (UTF16_MUNGED) matching
            # exactly what we need.
            return creds_for_charcnv.get_password().encode()

        # Extract the WDigest hash for the value specified by i.
        # Builds an htdigest compatible value
        DIGEST = "Digest"

        def get_wDigest(i, primary_wdigest, account_name, account_upn,
                        domain, dns_domain):
            if i == 1:
                user = account_name
                realm = domain
            elif i == 2:
                user = account_name.lower()
                realm = domain.lower()
            elif i == 3:
                user = account_name.upper()
                realm = domain.upper()
            elif i == 4:
                user = account_name
                realm = domain.upper()
            elif i == 5:
                user = account_name
                realm = domain.lower()
            elif i == 6:
                user = account_name.upper()
                realm = domain.lower()
            elif i == 7:
                user = account_name.lower()
                realm = domain.upper()
            elif i == 8:
                user = account_name
                realm = dns_domain.lower()
            elif i == 9:
                user = account_name.lower()
                realm = dns_domain.lower()
            elif i == 10:
                user = account_name.upper()
                realm = dns_domain.upper()
            elif i == 11:
                user = account_name
                realm = dns_domain.upper()
            elif i == 12:
                user = account_name
                realm = dns_domain.lower()
            elif i == 13:
                user = account_name.upper()
                realm = dns_domain.lower()
            elif i == 14:
                user = account_name.lower()
                realm = dns_domain.upper()
            elif i == 15:
                user = account_upn
                realm = ""
            elif i == 16:
                user = account_upn.lower()
                realm = ""
            elif i == 17:
                user = account_upn.upper()
                realm = ""
            elif i == 18:
                user = "%s\\%s" % (domain, account_name)
                realm = ""
            elif i == 19:
                user = "%s\\%s" % (domain.lower(), account_name.lower())
                realm = ""
            elif i == 20:
                user = "%s\\%s" % (domain.upper(), account_name.upper())
                realm = ""
            elif i == 21:
                user = account_name
                realm = DIGEST
            elif i == 22:
                user = account_name.lower()
                realm = DIGEST
            elif i == 23:
                user = account_name.upper()
                realm = DIGEST
            elif i == 24:
                user = account_upn
                realm = DIGEST
            elif i == 25:
                user = account_upn.lower()
                realm = DIGEST
            elif i == 26:
                user = account_upn.upper()
                realm = DIGEST
            elif i == 27:
                user = "%s\\%s" % (domain, account_name)
                realm = DIGEST
            elif i == 28:
                # Differs from spec, see tests
                user = "%s\\%s" % (domain.lower(), account_name.lower())
                realm = DIGEST
            elif i == 29:
                # Differs from spec, see tests
                user = "%s\\%s" % (domain.upper(), account_name.upper())
                realm = DIGEST
            else:
                user = ""

            digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                                 primary_wdigest)
            try:
                digest = binascii.hexlify(bytearray(digests.hashes[i - 1].hash))
                return "%s:%s:%s" % (user, realm, get_string(digest))
            except IndexError:
                return None

        # get the value for a virtualCrypt attribute.
        # look for an exact match on algorithm and rounds in supplemental creds
        # if not found calculate using Primary:CLEARTEXT
        # if no Primary:CLEARTEXT return the first supplementalCredential
        #    that matches the algorithm.
        def get_virtual_crypt_value(a, algorithm, rounds, username, account_name):
            sv = None
            fb = None
            b = get_package("Primary:userPassword")
            if b is not None:
                (sv, fb) = get_userPassword_hash(b, algorithm, rounds)
            if sv is None:
                # No exact match on algorithm and number of rounds
                # try and calculate one from the Primary:CLEARTEXT
                b = get_cleartext(attr_opts)
                if b is not None:
                    u8 = get_utf8(a, b, username or account_name)
                    if u8 is not None:
                        # in py2 using get_bytes should ensure u8 is unmodified
                        # in py3 it will be decoded
                        sv = get_crypt_value(str(algorithm), get_string(u8), rounds)
                if sv is None:
                    # Unable to calculate a hash with the specified
                    # number of rounds, fall back to the first hash using
                    # the specified algorithm
                    sv = fb
            if sv is None:
                return None
            return "{CRYPT}" + sv

        def get_userPassword_hash(blob, algorithm, rounds):
            up = ndr_unpack(drsblobs.package_PrimaryUserPasswordBlob, blob)
            SCHEME = "{CRYPT}"

            # Check that the NT hash or AES256 key have not been changed
            # without updating the user password hashes. This indicates that
            # password has been changed without updating the supplemental
            # credentials.
            if unicodePwd is not None:
                current_hash = unicodePwd
            elif aes256_key is not None:
                current_hash = aes256_key.value[:16]
            else:
                return None, None

            if current_hash != bytearray(up.current_nt_hash.hash):
                return None, None

            scheme_prefix = "$%d$" % algorithm
            prefix = scheme_prefix
            if rounds > 0:
                prefix = "$%d$rounds=%d" % (algorithm, rounds)
            scheme_match = None

            for h in up.hashes:
                # in PY2 this should just do nothing and in PY3 if bytes
                # it will decode them
                h_value = get_string(h.value)
                if (scheme_match is None and
                    h.scheme == SCHEME and
                        h_value.startswith(scheme_prefix)):
                    scheme_match = h_value
                if h.scheme == SCHEME and h_value.startswith(prefix):
                    return (h_value, scheme_match)

            # No match on the number of rounds, return the value of the
            # first matching scheme
            return (None, scheme_match)

        # Extract the rounds value from the options of a virtualCrypt attribute
        # i.e. options = "rounds=20;other=ignored;" will return 20
        # if the rounds option is not found or the value is not a number, 0 is returned
        # which indicates that the default number of rounds should be used.
        def get_rounds(opts):
            val = get_option(opts, "rounds")
            if val is None:
                return 0
            try:
                return int(val)
            except ValueError:
                return 0

        def get_unicode_pwd_hash(pwd):
            # We can't read unicodePwd directly, but we can regenerate
            # it from msDS-ManagedPassword
            tmp = credentials.Credentials()
            tmp.set_anonymous()
            tmp.set_utf16_password(pwd)
            return tmp.get_nt_hash()

        # We use sort here in order to have a predictable processing order
        for a in sorted(virtual_attributes.keys()):
            vattr = None
            for ra in requested_attrs:
                if ra["vattr"] is None:
                    continue
                if ra["attr"].lower() != a.lower():
                    continue
                vattr = ra
                break
            if vattr is None:
                continue
            attr_opts = vattr["opts"]

            if a == "virtualClearTextUTF8":
                b = get_cleartext(attr_opts)
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                v = u8
            elif a == "virtualClearTextUTF16":
                v = get_cleartext(attr_opts)
                if v is None:
                    continue
            elif a == "virtualSSHA":
                b = get_cleartext(attr_opts)
                if b is None:
                    continue
                u8 = get_utf8(a, b, username or account_name)
                if u8 is None:
                    continue
                salt = os.urandom(4)
                h = hashlib.sha1()
                h.update(u8)
                h.update(salt)
                bv = h.digest() + salt
                v = "{SSHA}" + base64.b64encode(bv).decode('utf8')
            elif a == "virtualCryptSHA256":
                rounds = get_rounds(attr_opts)
                x = get_virtual_crypt_value(a, 5, rounds, username, account_name)
                if x is None:
                    continue
                v = x
            elif a == "virtualCryptSHA512":
                rounds = get_rounds(attr_opts)
                x = get_virtual_crypt_value(a, 6, rounds, username, account_name)
                if x is None:
                    continue
                v = x
            elif a == "virtualSambaGPG":
                # Samba adds 'Primary:SambaGPG' at the end.
                # When Windows sets the password it keeps
                # 'Primary:SambaGPG' and rotates it to
                # the beginning. So we can only use the value,
                # if it is the last one.
                v = get_package("Primary:SambaGPG", min_idx=-1)
                if v is None:
                    continue
            elif a == "virtualKerberosSalt":
                v = kerberos_salt
                if v is None:
                    continue
            elif a == "unicodePwd" and unicodePwd is None:
                if "Primary:CLEARTEXT" in calculated and not get_option(attr_opts, "previous"):
                    v = get_unicode_pwd_hash(calculated["Primary:CLEARTEXT"])
                elif "OLDCLEARTEXT" in calculated and get_option(attr_opts, "previous"):
                    v = get_unicode_pwd_hash(calculated["OLDCLEARTEXT"])
                else:
                    continue
            elif a.startswith("virtualWDigest"):
                primary_wdigest = get_package("Primary:WDigest")
                if primary_wdigest is None:
                    continue
                x = a[len("virtualWDigest"):]
                try:
                    i = int(x)
                except ValueError:
                    continue
                domain = samdb.domain_netbios_name()
                dns_domain = samdb.domain_dns_name()
                v = get_wDigest(i, primary_wdigest, account_name, account_upn, domain, dns_domain)
                if v is None:
                    continue
            elif a == "virtualManagedPasswordQueryTime":
                if "GMSA:query_time" not in calculated:
                    continue
                v = str(calculated["GMSA:query_time"])
            else:
                continue
            obj[a] = ldb.MessageElement(v, ldb.FLAG_MOD_REPLACE, vattr["raw_attr"])

        def get_src_attrname(srcattrg):
            srcattrl = srcattrg.lower()
            srcattr = None
            for k in obj.keys():
                if srcattrl != k.lower():
                    continue
                srcattr = k
                break
            return srcattr

        def get_src_time_float(srcattr):
            if srcattr not in obj:
                return None
            vstr = str(obj[srcattr][0])
            if vstr.endswith(".0Z"):
                vut = ldb.string_to_time(vstr)
                vfl = float(vut)
                return vfl

            try:
                vnt = int(vstr)
            except ValueError as e:
                return None
            # 0 or 9223372036854775807 mean no value too
            if vnt == 0:
                return None
            if vnt >= 0x7FFFFFFFFFFFFFFF:
                return None
            vfl = nttime2float(vnt)
            return vfl

        def get_generalizedtime(srcattr):
            vfl = get_src_time_float(srcattr)
            if vfl is None:
                return None
            vut = int(vfl)
            try:
                v = "%s" % ldb.timestring(vut)
            except OSError as e:
                if e.errno == errno.EOVERFLOW:
                    return None
                raise
            return v

        def get_unixepoch(srcattr):
            vfl = get_src_time_float(srcattr)
            if vfl is None:
                return None
            vut = int(vfl)
            v = "%d" % vut
            return v

        def get_timespec(srcattr):
            vfl = get_src_time_float(srcattr)
            if vfl is None:
                return None
            v = "%.9f" % vfl
            return v

        generated_formats = {}
        for fm in formats:
            for ra in requested_attrs:
                if ra["vformat"] is None:
                    continue
                if ra["vformat"] != fm:
                    continue

                srcattr = get_src_attrname(ra["attr"])
                if srcattr is not None:
                    an = "%s;format=%s" % (srcattr, fm)
                else:
                    srcattr = an = get_src_attrname(ra["raw_attr"])
                if srcattr is None:
                    continue
                if an in generated_formats:
                    continue
                generated_formats[an] = fm

                v = None
                if fm == "GeneralizedTime":
                    v = get_generalizedtime(srcattr)
                elif fm == "UnixTime":
                    v = get_unixepoch(srcattr)
                elif fm == "TimeSpec":
                    v = get_timespec(srcattr)
                if v is None:
                    continue
                obj[an] = ldb.MessageElement(v, ldb.FLAG_MOD_REPLACE, an)

        # Now filter out implicit attributes
        for delname in obj.keys():
            keep = False
            for ra in requested_attrs:
                if delname.lower() != ra["raw_attr"].lower():
                    continue
                keep = True
                break
            if keep:
                continue

            dattr = None
            for ia in implicit_attrs:
                if delname.lower() != ia["attr"].lower():
                    continue
                dattr = ia
                break
            if dattr is None:
                continue

            if has_wildcard_attr and not dattr["is_hidden"]:
                continue
            del obj[delname]
        return obj

    def parse_attributes(self, attributes):

        if attributes is None:
            raise CommandError("Please specify --attributes")
        attrs = attributes.split(',')
        password_attrs = []
        for pa in attrs:
            pa = pa.lstrip().rstrip()
            for da in disabled_virtual_attributes.keys():
                if pa.lower() == da.lower():
                    r = disabled_virtual_attributes[da]["reason"]
                    raise CommandError("Virtual attribute '%s' not supported: %s" % (
                                       da, r))
            for va in virtual_attributes.keys():
                if pa.lower() == va.lower():
                    # Take the real name
                    pa = va
                    break
            password_attrs += [pa]

        return password_attrs
