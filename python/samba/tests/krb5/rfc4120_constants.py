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

# PAData types
PADATA_ENC_TIMESTAMP = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ENC-TIMESTAMP'))
PADATA_ETYPE_INFO2 = int(
    krb5_asn1.PADataTypeValues('kRB5-PADATA-ETYPE-INFO2'))

# Error codes
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
KDC_ERR_PREAUTH_FAILED      = 24
KDC_ERR_PREAUTH_REQUIRED    = 25
KDC_ERR_SKEW                = 37

# Name types
NT_UNKNOWN   = int(krb5_asn1.NameTypeValues('kRB5-NT-UNKNOWN'))
NT_PRINCIPAL = int(krb5_asn1.NameTypeValues('kRB5-NT-PRINCIPAL'))
NT_SRV_INST  = int(krb5_asn1.NameTypeValues('kRB5-NT-SRV-INST'))
NT_ENTERPRISE_PRINCIPAL = int(krb5_asn1.NameTypeValues(
    'kRB5-NT-ENTERPRISE-PRINCIPAL'))
