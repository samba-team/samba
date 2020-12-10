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
KRB_AS_REP = int(krb5_asn1.MessageTypeValues('krb-as-rep'))
KRB_TGS_REP = int(krb5_asn1.MessageTypeValues('krb-tgs-rep'))

# PAData types
PADATA_ENC_TIMESTAMP = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ENC-TIMESTAMP'))
PADATA_ETYPE_INFO2 = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ETYPE-INFO2'))

# Error codes
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
KDC_ERR_PREAUTH_FAILED = 24
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_BADMATCH = 36
KDC_ERR_SKEW = 37

# Name types
NT_UNKNOWN = int(krb5_asn1.NameTypeValues('kRB5-NT-UNKNOWN'))
NT_PRINCIPAL = int(krb5_asn1.NameTypeValues('kRB5-NT-PRINCIPAL'))
NT_SRV_INST = int(krb5_asn1.NameTypeValues('kRB5-NT-SRV-INST'))
NT_ENTERPRISE_PRINCIPAL = int(krb5_asn1.NameTypeValues(
    'kRB5-NT-ENTERPRISE-PRINCIPAL'))

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
