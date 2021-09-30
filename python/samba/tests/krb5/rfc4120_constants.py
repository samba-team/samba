# Unix SMB/CIFS implementation.
# Copyright (C) 2020 Catalyst.Net Ltd
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

import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1

# Encryption types
AES256_CTS_HMAC_SHA1_96 = int(
    krb5_asn1.EncryptionTypeValues('kRB5-ENCTYPE-AES256-CTS-HMAC-SHA1-96'))
AES128_CTS_HMAC_SHA1_96 = int(
    krb5_asn1.EncryptionTypeValues('kRB5-ENCTYPE-AES128-CTS-HMAC-SHA1-96'))
ARCFOUR_HMAC_MD5 = int(
    krb5_asn1.EncryptionTypeValues('kRB5-ENCTYPE-ARCFOUR-HMAC-MD5'))

# Message types
KRB_ERROR = int(krb5_asn1.MessageTypeValues('krb-error'))
KRB_AP_REQ = int(krb5_asn1.MessageTypeValues('krb-ap-req'))
KRB_AS_REP = int(krb5_asn1.MessageTypeValues('krb-as-rep'))
KRB_AS_REQ = int(krb5_asn1.MessageTypeValues('krb-as-req'))
KRB_TGS_REP = int(krb5_asn1.MessageTypeValues('krb-tgs-rep'))
KRB_TGS_REQ = int(krb5_asn1.MessageTypeValues('krb-tgs-req'))

# PAData types
PADATA_ENC_TIMESTAMP = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ENC-TIMESTAMP'))
PADATA_ENCRYPTED_CHALLENGE = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ENCRYPTED-CHALLENGE'))
PADATA_ETYPE_INFO = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ETYPE-INFO'))
PADATA_ETYPE_INFO2 = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ETYPE-INFO2'))
PADATA_FOR_USER = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-FOR-USER'))
PADATA_FX_COOKIE = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-FX-COOKIE'))
PADATA_FX_ERROR = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-FX-ERROR'))
PADATA_FX_FAST = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-FX-FAST'))
PADATA_KDC_REQ = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-KDC-REQ'))
PADATA_PAC_OPTIONS = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-PAC-OPTIONS'))
PADATA_PAC_REQUEST = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-PA-PAC-REQUEST'))
PADATA_PK_AS_REQ = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-PK-AS-REQ'))
PADATA_PK_AS_REP_19 = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-PK-AS-REP-19'))
PADATA_PW_SALT = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-PW-SALT'))
PADATA_SUPPORTED_ETYPES = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-SUPPORTED-ETYPES'))

# Error codes
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
KDC_ERR_POLICY = 12
KDC_ERR_BADOPTION = 13
KDC_ERR_ETYPE_NOSUPP = 14
KDC_ERR_SUMTYPE_NOSUPP = 15
KDC_ERR_PREAUTH_FAILED = 24
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_BAD_INTEGRITY = 31
KDC_ERR_NOT_US = 35
KDC_ERR_BADMATCH = 36
KDC_ERR_SKEW = 37
KDC_ERR_MODIFIED = 41
KDC_ERR_INAPP_CKSUM = 50
KDC_ERR_GENERIC = 60
KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS = 93

# Extended error types
KERB_AP_ERR_TYPE_SKEW_RECOVERY = int(
    krb5_asn1.KerbErrorDataTypeValues('kERB-AP-ERR-TYPE-SKEW-RECOVERY'))
KERB_ERR_TYPE_EXTENDED = int(
    krb5_asn1.KerbErrorDataTypeValues('kERB-ERR-TYPE-EXTENDED'))

# Name types
NT_UNKNOWN = int(krb5_asn1.NameTypeValues('kRB5-NT-UNKNOWN'))
NT_PRINCIPAL = int(krb5_asn1.NameTypeValues('kRB5-NT-PRINCIPAL'))
NT_SRV_HST = int(krb5_asn1.NameTypeValues('kRB5-NT-SRV-HST'))
NT_SRV_INST = int(krb5_asn1.NameTypeValues('kRB5-NT-SRV-INST'))
NT_ENTERPRISE_PRINCIPAL = int(krb5_asn1.NameTypeValues(
    'kRB5-NT-ENTERPRISE-PRINCIPAL'))
NT_WELLKNOWN = int(krb5_asn1.NameTypeValues('kRB5-NT-WELLKNOWN'))

# Authorization data ad-type values

AD_IF_RELEVANT = 1
AD_INTENDED_FOR_SERVER = 2
AD_INTENDED_FOR_APPLICATION_CLASS = 3
AD_KDC_ISSUED = 4
AD_AND_OR = 5
AD_MANDATORY_TICKET_EXTENSIONS = 6
AD_IN_TICKET_EXTENSIONS = 7
AD_MANDATORY_FOR_KDC = 8
AD_INITIAL_VERIFIED_CAS = 9
AD_FX_FAST_ARMOR = 71
AD_FX_FAST_USED = 72
AD_WIN2K_PAC = 128
AD_SIGNTICKET = 512

# Key usage numbers
# RFC 4120 Section 7.5.1.  Key Usage Numbers
KU_PA_ENC_TIMESTAMP = 1
''' AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
    client key (section 5.2.7.2) '''
KU_TICKET = 2
''' AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
    application session key), encrypted with the service key
    (section 5.3) '''
KU_AS_REP_ENC_PART = 3
''' AS-REP encrypted part (includes tgs session key or application
    session key), encrypted with the client key (section 5.4.2) '''
KU_TGS_REQ_AUTH_DAT_SESSION = 4
''' TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the tgs
    session key (section 5.4.1) '''
KU_TGS_REQ_AUTH_DAT_SUBKEY = 5
''' TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the tgs
    authenticator subkey (section 5.4.1) '''
KU_TGS_REQ_AUTH_CKSUM = 6
''' TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed
    with the tgs session key (section 5.5.1) '''
KU_TGS_REQ_AUTH = 7
''' TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes tgs
    authenticator subkey), encrypted with the tgs session key
    (section 5.5.1) '''
KU_TGS_REP_ENC_PART_SESSION = 8
''' TGS-REP encrypted part (includes application session key),
    encrypted with the tgs session key (section 5.4.2) '''
KU_TGS_REP_ENC_PART_SUB_KEY = 9
''' TGS-REP encrypted part (includes application session key),
    encrypted with the tgs authenticator subkey (section 5.4.2) '''
KU_AP_REQ_AUTH_CKSUM = 10
''' AP-REQ Authenticator cksum, keyed with the application session
    key (section 5.5.1) '''
KU_AP_REQ_AUTH = 11
''' AP-REQ Authenticator (includes application authenticator
    subkey), encrypted with the application session key (section 5.5.1) '''
KU_AP_REQ_ENC_PART = 12
''' AP-REP encrypted part (includes application session subkey),
    encrypted with the application session key (section 5.5.2) '''
KU_KRB_PRIV = 13
''' KRB-PRIV encrypted part, encrypted with a key chosen by the
    application (section 5.7.1) '''
KU_KRB_CRED = 14
''' KRB-CRED encrypted part, encrypted with a key chosen by the
    application (section 5.8.1) '''
KU_KRB_SAFE_CKSUM = 15
''' KRB-SAFE cksum, keyed with a key chosen by the application
    (section 5.6.1) '''
KU_NON_KERB_SALT = 16
KU_NON_KERB_CKSUM_SALT = 17

KU_ACCEPTOR_SEAL = 22
KU_ACCEPTOR_SIGN = 23
KU_INITIATOR_SEAL = 24
KU_INITIATOR_SIGN = 25

KU_FAST_REQ_CHKSUM = 50
KU_FAST_ENC = 51
KU_FAST_REP = 52
KU_FAST_FINISHED = 53
KU_ENC_CHALLENGE_CLIENT = 54
KU_ENC_CHALLENGE_KDC = 55

# Armor types
FX_FAST_ARMOR_AP_REQUEST = 1
