/* Generated from /home/data/samba/samba4/svn/source/heimdal/lib/hx509/ocsp.asn1 */
/* Do not edit */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <krb5-types.h>
#include <ocsp_asn1.h>
#include <asn1_err.h>
#include <der.h>
#include <parse_units.h>

static unsigned oid_id_pkix_ocsp_basic_variable_num[10] =  {1, 3, 6, 1, 5, 5, 7, 48, 1, 1 };
static const heim_oid oid_id_pkix_ocsp_basic_variable = { 10, oid_id_pkix_ocsp_basic_variable_num };

const heim_oid *oid_id_pkix_ocsp_basic(void)
{
return &oid_id_pkix_ocsp_basic_variable;
}

