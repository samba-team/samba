/*
 * Copyright (c) 2004 - 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "hx_locl.h"
#include <wind.h>
#include "char_map.h"

/**
 * @page page_name PKIX/X.509 Names
 *
 * There are several names in PKIX/X.509, GeneralName and Name.
 *
 * A Name consists of an ordered list of Relative Distinguished Names
 * (RDN). Each RDN consists of an unordered list of typed strings. The
 * types are defined by OID and have long and short description. For
 * example id-at-commonName (2.5.4.3) have the long name CommonName
 * and short name CN. The string itself can be of several encoding,
 * UTF8, UTF16, Teltex string, etc. The type limit what encoding
 * should be used.
 *
 * GeneralName is a broader nametype that can contains al kind of
 * stuff like Name, IP addresses, partial Name, etc.
 *
 * Name is mapped into a hx509_name object.
 *
 * Parse and string name into a hx509_name object with hx509_parse_name(),
 * make it back into string representation with hx509_name_to_string().
 *
 * Name string are defined rfc2253, rfc1779 and X.501.
 *
 * See the library functions here: @ref hx509_name
 */

static const struct {
    const char *n;
    const heim_oid *o;
    int type_choice; /* Preference for DirectoryString choice; 0 -> no pref */
    wind_profile_flags flags;
    /*
     * RFC52380 imposes maximum lengths for some strings in Names.  These are
     * ASN.1 size limits.  We should implement these in our copy of the PKIX
     * ASN.1 module.  For now we treat them as maximum byte counts rather than
     * maximum character counts, and we encode and enforce them here.
     *
     * 0 -> no max
     *
     * Some of these attributes aren't of type DirectoryString, so our
     * type_choice isn't really correct.  We're not really set up for
     * attributes whose types aren't DirectoryString or one of its choice arms'
     * type, much less are we set up for non-string attribute value types.
     */
    size_t max_bytes;
} no[] = {
    { "C", &asn1_oid_id_at_countryName,
        choice_DirectoryString_printableString, 0, 2 },
    { "CN", &asn1_oid_id_at_commonName, 0, 0, ub_common_name },
    { "DC", &asn1_oid_id_domainComponent, choice_DirectoryString_ia5String,
        0, 63 }, /* DNS label */
    { "L", &asn1_oid_id_at_localityName, 0, 0, ub_locality_name },
    { "O", &asn1_oid_id_at_organizationName, 0, 0, ub_organization_name },
    { "OU", &asn1_oid_id_at_organizationalUnitName, 0, 0,
        ub_organizational_unit_name },
    { "S", &asn1_oid_id_at_stateOrProvinceName, 0, 0, ub_state_name },
    { "STREET", &asn1_oid_id_at_streetAddress, 0, 0, 0 }, /* ENOTSUP */
    { "UID", &asn1_oid_id_Userid, 0, 0, ub_numeric_user_id_length },
    { "emailAddress", &asn1_oid_id_pkcs9_emailAddress,
        choice_DirectoryString_ia5String, 0, ub_emailaddress_length },
    /* This is for DevID certificates and maybe others */
    { "serialNumber", &asn1_oid_id_at_serialNumber, 0, 0, ub_serial_number },
    /* These are for TPM 2.0 Endorsement Key Certificates (EKCerts) */
    { "TPMManufacturer", &asn1_oid_tcg_at_tpmManufacturer, 0, 0,
        ub_emailaddress_length },
    { "TPMModel", &asn1_oid_tcg_at_tpmModel, 0, 0, ub_emailaddress_length },
    { "TPMVersion", &asn1_oid_tcg_at_tpmVersion, 0, 0, ub_emailaddress_length },
};

static char *
quote_string(const char *f, size_t len, int flags, size_t *rlen)
{
    size_t i, j, tolen;
    const unsigned char *from = (const unsigned char *)f;
    unsigned char *to;

    tolen = len * 3 + 1;
    to = malloc(tolen);
    if (to == NULL)
	return NULL;

    for (i = 0, j = 0; i < len; i++) {
	unsigned char map = char_map[from[i]] & flags;
	if (i == 0 && (map & Q_RFC2253_QUOTE_FIRST)) {
	    to[j++] = '\\';
	    to[j++] = from[i];
	} else if ((i + 1) == len && (map & Q_RFC2253_QUOTE_LAST)) {

	    to[j++] = '\\';
	    to[j++] = from[i];
	} else if (map & Q_RFC2253_QUOTE) {
	    to[j++] = '\\';
	    to[j++] = from[i];
	} else if (map & Q_RFC2253_HEX) {
	    int l = snprintf((char *)&to[j], tolen - j - 1,
			     "#%02x", (unsigned char)from[i]);
	    j += l;
	} else {
	    to[j++] = from[i];
	}
    }
    to[j] = '\0';
    assert(j < tolen);
    *rlen = j;
    return (char *)to;
}


static int
append_string(char **str, size_t *total_len, const char *ss,
	      size_t len, int quote)
{
    char *s, *qs;

    if (quote)
	qs = quote_string(ss, len, Q_RFC2253, &len);
    else
	qs = rk_UNCONST(ss);

    s = realloc(*str, len + *total_len + 1);
    if (s == NULL)
	_hx509_abort("allocation failure"); /* XXX */
    memcpy(s + *total_len, qs, len);
    if (qs != ss)
	free(qs);
    s[*total_len + len] = '\0';
    *str = s;
    *total_len += len;
    return 0;
}

static char *
oidtostring(const heim_oid *type, int *type_choice)
{
    char *s;
    size_t i;

    if (type_choice)
        *type_choice = choice_DirectoryString_utf8String;

    for (i = 0; i < sizeof(no)/sizeof(no[0]); i++) {
	if (der_heim_oid_cmp(no[i].o, type) == 0) {
            if (type_choice && no[i].type_choice)
                *type_choice = no[i].type_choice;
	    return strdup(no[i].n);
        }
    }
    if (der_print_heim_oid(type, '.', &s) != 0)
	return NULL;
    return s;
}

static size_t
oidtomaxlen(const heim_oid *type)
{
    size_t i;

    for (i = 0; i < sizeof(no)/sizeof(no[0]); i++) {
	if (der_heim_oid_cmp(no[i].o, type) == 0)
	    return no[i].max_bytes;
    }
    return 0;
}

static int
stringtooid(const char *name, size_t len, heim_oid *oid)
{
    int ret;
    size_t i;
    char *s;

    memset(oid, 0, sizeof(*oid));

    for (i = 0; i < sizeof(no)/sizeof(no[0]); i++) {
	if (strncasecmp(no[i].n, name, len) == 0)
	    return der_copy_oid(no[i].o, oid);
    }
    s = malloc(len + 1);
    if (s == NULL)
	return ENOMEM;
    memcpy(s, name, len);
    s[len] = '\0';
    ret = der_parse_heim_oid(s, ".", oid);
    free(s);
    return ret;
}

/**
 * Convert the hx509 name object into a printable string.
 * The resulting string should be freed with free().
 *
 * @param name name to print
 * @param str the string to return
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_to_string(const hx509_name name, char **str)
{
    return _hx509_Name_to_string(&name->der_name, str);
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_Name_to_string(const Name *n, char **str)
{
    size_t total_len = 0;
    size_t i, j, m;
    int ret;

    *str = strdup("");
    if (*str == NULL)
	return ENOMEM;

    for (m = n->u.rdnSequence.len; m > 0; m--) {
	size_t len;
	i = m - 1;

	for (j = 0; j < n->u.rdnSequence.val[i].len; j++) {
	    DirectoryString *ds = &n->u.rdnSequence.val[i].val[j].value;
	    char *oidname;
	    char *ss;

	    oidname = oidtostring(&n->u.rdnSequence.val[i].val[j].type, NULL);

	    switch(ds->element) {
	    case choice_DirectoryString_ia5String:
		ss = ds->u.ia5String.data;
		len = ds->u.ia5String.length;
		break;
	    case choice_DirectoryString_printableString:
		ss = ds->u.printableString.data;
		len = ds->u.printableString.length;
		break;
	    case choice_DirectoryString_utf8String:
		ss = ds->u.utf8String;
		len = strlen(ss);
		break;
	    case choice_DirectoryString_bmpString: {
	        const uint16_t *bmp = ds->u.bmpString.data;
		size_t bmplen = ds->u.bmpString.length;
		size_t k;

		ret = wind_ucs2utf8_length(bmp, bmplen, &k);
		if (ret) {
                    free(oidname);
                    free(*str);
                    *str = NULL;
		    return ret;
                }

		ss = malloc(k + 1);
		if (ss == NULL)
		    _hx509_abort("allocation failure"); /* XXX */
		ret = wind_ucs2utf8(bmp, bmplen, ss, NULL);
		if (ret) {
                    free(oidname);
		    free(ss);
                    free(*str);
                    *str = NULL;
		    return ret;
		}
		ss[k] = '\0';
		len = k;
		break;
	    }
	    case choice_DirectoryString_teletexString:
		ss = ds->u.teletexString;
		len = strlen(ss);
		break;
	    case choice_DirectoryString_universalString: {
	        const uint32_t *uni = ds->u.universalString.data;
		size_t unilen = ds->u.universalString.length;
		size_t k;

		ret = wind_ucs4utf8_length(uni, unilen, &k);
		if (ret) {
                    free(oidname);
                    free(*str);
                    *str = NULL;
		    return ret;
                }

		ss = malloc(k + 1);
		if (ss == NULL)
		    _hx509_abort("allocation failure"); /* XXX */
		ret = wind_ucs4utf8(uni, unilen, ss, NULL);
		if (ret) {
		    free(ss);
                    free(oidname);
                    free(*str);
                    *str = NULL;
		    return ret;
		}
		ss[k] = '\0';
		len = k;
		break;
	    }
	    default:
		_hx509_abort("unknown directory type: %d", ds->element);
		exit(1);
	    }
	    append_string(str, &total_len, oidname, strlen(oidname), 0);
	    free(oidname);
	    append_string(str, &total_len, "=", 1, 0);
	    append_string(str, &total_len, ss, len, 1);
	    if (ds->element == choice_DirectoryString_bmpString ||
		ds->element == choice_DirectoryString_universalString)
	    {
		free(ss);
	    }
	    if (j + 1 < n->u.rdnSequence.val[i].len)
		append_string(str, &total_len, "+", 1, 0);
	}

	if (i > 0)
	    append_string(str, &total_len, ",", 1, 0);
    }
    return 0;
}

#define COPYCHARARRAY(_ds,_el,_l,_n)			\
        (_l) = strlen(_ds->u._el);			\
	(_n) = malloc((_l + 1) * sizeof((_n)[0]));	\
	if ((_n) == NULL)				\
	    return ENOMEM;				\
	for (i = 0; i < (_l); i++)			\
	    (_n)[i] = _ds->u._el[i]


#define COPYVALARRAY(_ds,_el,_l,_n)			\
        (_l) = _ds->u._el.length;			\
	(_n) = malloc((_l + 1) * sizeof((_n)[0]));	\
	if ((_n) == NULL)				\
	    return ENOMEM;				\
	for (i = 0; i < (_l); i++)			\
	    (_n)[i] = _ds->u._el.data[i]

#define COPYVOIDARRAY(_ds,_el,_l,_n)			\
        (_l) = _ds->u._el.length;			\
	(_n) = malloc((_l + 1) * sizeof((_n)[0]));	\
	if ((_n) == NULL)				\
	    return ENOMEM;				\
	for (i = 0; i < (_l); i++)			\
	    (_n)[i] = ((unsigned char *)_ds->u._el.data)[i]



static int
dsstringprep(const DirectoryString *ds, uint32_t **rname, size_t *rlen)
{
    wind_profile_flags flags;
    size_t i, len;
    int ret = 0;
    uint32_t *name;

    *rname = NULL;
    *rlen = 0;

    switch(ds->element) {
    case choice_DirectoryString_ia5String:
	flags = WIND_PROFILE_LDAP;
	COPYVOIDARRAY(ds, ia5String, len, name);
	break;
    case choice_DirectoryString_printableString:
	flags = WIND_PROFILE_LDAP;
	flags |= WIND_PROFILE_LDAP_CASE_EXACT_ATTRIBUTE;
	COPYVOIDARRAY(ds, printableString, len, name);
	break;
    case choice_DirectoryString_teletexString:
	flags = WIND_PROFILE_LDAP_CASE;
	COPYCHARARRAY(ds, teletexString, len, name);
	break;
    case choice_DirectoryString_bmpString:
	flags = WIND_PROFILE_LDAP;
	COPYVALARRAY(ds, bmpString, len, name);
	break;
    case choice_DirectoryString_universalString:
	flags = WIND_PROFILE_LDAP;
	COPYVALARRAY(ds, universalString, len, name);
	break;
    case choice_DirectoryString_utf8String:
	flags = WIND_PROFILE_LDAP;
	ret = wind_utf8ucs4_length(ds->u.utf8String, &len);
	if (ret)
	    return ret;
	name = malloc((len + 1) * sizeof(name[0]));
	if (name == NULL)
	    return ENOMEM;
	ret = wind_utf8ucs4(ds->u.utf8String, name, &len);
	if (ret) {
	    free(name);
	    return ret;
	}
	break;
    default:
	_hx509_abort("unknown directory type: %d", ds->element);
    }

    *rlen = len;
    /* try a couple of times to get the length right, XXX gross */
    for (i = 0; i < 4; i++) {
	*rlen = *rlen * 2;
	if ((*rname = malloc((rlen[0] + 1) * sizeof((*rname)[0]))) == NULL) {
            ret = ENOMEM;
            break;
        }

	ret = wind_stringprep(name, len, *rname, rlen, flags);
	if (ret == WIND_ERR_OVERRUN) {
	    free(*rname);
	    *rname = NULL;
	    continue;
	} else
	    break;
    }
    free(name);
    if (ret) {
	if (*rname)
	    free(*rname);
	*rname = NULL;
	*rlen = 0;
	return ret;
    }

    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_name_ds_cmp(const DirectoryString *ds1,
		   const DirectoryString *ds2,
		   int *diff)
{
    uint32_t *ds1lp, *ds2lp;
    size_t ds1len, ds2len, i;
    int ret;

    ret = dsstringprep(ds1, &ds1lp, &ds1len);
    if (ret)
	return ret;
    ret = dsstringprep(ds2, &ds2lp, &ds2len);
    if (ret) {
	free(ds1lp);
	return ret;
    }

    if (ds1len != ds2len)
	*diff = ds1len - ds2len;
    else {
	for (i = 0; i < ds1len; i++) {
	    *diff = ds1lp[i] - ds2lp[i];
	    if (*diff)
		break;
	}
    }
    free(ds1lp);
    free(ds2lp);

    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_name_cmp(const Name *n1, const Name *n2, int *c)
{
    int ret;
    size_t i, j;

    *c = n1->u.rdnSequence.len - n2->u.rdnSequence.len;
    if (*c)
	return 0;

    for (i = 0 ; i < n1->u.rdnSequence.len; i++) {
	*c = n1->u.rdnSequence.val[i].len - n2->u.rdnSequence.val[i].len;
	if (*c)
	    return 0;

	for (j = 0; j < n1->u.rdnSequence.val[i].len; j++) {
	    *c = der_heim_oid_cmp(&n1->u.rdnSequence.val[i].val[j].type,
				  &n1->u.rdnSequence.val[i].val[j].type);
	    if (*c)
		return 0;

	    ret = _hx509_name_ds_cmp(&n1->u.rdnSequence.val[i].val[j].value,
				     &n2->u.rdnSequence.val[i].val[j].value,
				     c);
	    if (ret)
		return ret;
	    if (*c)
		return 0;
	}
    }
    *c = 0;
    return 0;
}

/**
 * Compare to hx509 name object, useful for sorting.
 *
 * @param n1 a hx509 name object.
 * @param n2 a hx509 name object.
 *
 * @return 0 the objects are the same, returns > 0 is n2 is "larger"
 * then n2, < 0 if n1 is "smaller" then n2.
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_cmp(hx509_name n1, hx509_name n2)
{
    int ret, diff;
    ret = _hx509_name_cmp(&n1->der_name, &n2->der_name, &diff);
    if (ret)
	return ret;
    return diff;
}


HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_name_from_Name(const Name *n, hx509_name *name)
{
    int ret;
    *name = calloc(1, sizeof(**name));
    if (*name == NULL)
	return ENOMEM;
    ret = copy_Name(n, &(*name)->der_name);
    if (ret) {
	free(*name);
	*name = NULL;
    }
    return ret;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_name_modify(hx509_context context,
		   Name *name,
		   int append,
		   const heim_oid *oid,
		   const char *str)
{
    RelativeDistinguishedName rdn;
    size_t max_len = oidtomaxlen(oid);
    char *s = NULL;
    int type_choice = choice_DirectoryString_printableString;
    int ret;

    /*
     * Check string length upper bounds.
     *
     * Because we don't have these bounds in our copy of the PKIX ASN.1 module,
     * and because we might like to catch these early anyways, we enforce them
     * here.
     */
    if (max_len && strlen(str) > max_len) {
        char *a = oidtostring(oid, &type_choice);

        ret = HX509_PARSING_NAME_FAILED;
        hx509_set_error_string(context, 0, ret, "RDN attribute %s value too "
                               "long (max %llu): %s", a ? a : "<unknown>",
                               max_len, str);
        free(a);
        return ret;
    }

    memset(&rdn, 0, sizeof(rdn));
    if ((rdn.val = malloc(sizeof(rdn.val[0]))) == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "Out of memory");
	return ENOMEM;
    }
    rdn.len = 1;

    /*
     * How best to pick a type for this attribute value?
     *
     * Options:
     *
     * 1) the API deals only in UTF-8, let the callers convert to/from UTF-8
     *    and whatever the current locale wants
     *
     * 2) use the best type for the codeset of the current locale.
     *
     * We choose (1).
     *
     * However, for some cases we really should prefer other types when the
     * input string is all printable ASCII.
     */
    rdn.val[0].value.element = type_choice;
    if ((s = strdup(str)) == NULL ||
        der_copy_oid(oid, &rdn.val[0].type)) {
        free(rdn.val);
        free(s);
	return hx509_enomem(context);
    }
    switch (rdn.val[0].value.element) {
    /* C strings: */
    case choice_DirectoryString_utf8String:
        rdn.val[0].value.u.utf8String = s;
        break;
    case choice_DirectoryString_teletexString:
        rdn.val[0].value.u.teletexString = s;
        break;

    /* Length and pointer */
    case choice_DirectoryString_ia5String:
        rdn.val[0].value.u.ia5String.data = s;
        rdn.val[0].value.u.ia5String.length = strlen(s);
        break;
    case choice_DirectoryString_printableString:
        rdn.val[0].value.u.printableString.data = s;
        rdn.val[0].value.u.printableString.length = strlen(s);
        break;
    case choice_DirectoryString_universalString:
        free(s);
        free(rdn.val);
	hx509_set_error_string(context, 0, ENOTSUP, "UniversalString not supported");
        return ENOTSUP;
    case choice_DirectoryString_bmpString:
        free(s);
        free(rdn.val);
	hx509_set_error_string(context, 0, ENOTSUP, "BMPString not supported");
        return ENOTSUP;
    default:
        free(s);
        free(rdn.val);
	hx509_set_error_string(context, 0, ENOTSUP,
                               "Internal error; unknown DirectoryString choice");
        return ENOTSUP;
    }

    /* Append RDN.  If the caller wanted to prepend instead, we'll rotate. */
    ret = add_RDNSequence(&name->u.rdnSequence, &rdn);
    free_RelativeDistinguishedName(&rdn);

    if (ret || append || name->u.rdnSequence.len < 2)
        return ret;

    /* Rotate */
    rdn = name->u.rdnSequence.val[name->u.rdnSequence.len - 1];
    memmove(&name->u.rdnSequence.val[1],
            &name->u.rdnSequence.val[0],
            (name->u.rdnSequence.len - 1) *
            sizeof(name->u.rdnSequence.val[0]));
    name->u.rdnSequence.val[0] = rdn;
    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_empty_name(hx509_context context, hx509_name *name)
{
    if ((*name = calloc(1, sizeof(**name))) == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    (*name)->der_name.element = choice_Name_rdnSequence;
    (*name)->der_name.u.rdnSequence.val = 0;
    (*name)->der_name.u.rdnSequence.len = 0;
    return 0;
}

/**
 * Parse a string into a hx509 name object.
 *
 * @param context A hx509 context.
 * @param str a string to parse.
 * @param name the resulting object, NULL in case of error.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_parse_name(hx509_context context, const char *str, hx509_name *name)
{
    const char *p, *q;
    size_t len;
    hx509_name n;
    int ret;

    *name = NULL;

    n = calloc(1, sizeof(*n));
    if (n == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }

    n->der_name.element = choice_Name_rdnSequence;

    p = str;

    while (p != NULL && *p != '\0') {
	heim_oid oid;
	int last;

	q = strchr(p, ',');
	if (q) {
	    len = (q - p);
	    last = 1;
	} else {
	    len = strlen(p);
	    last = 0;
	}

	q = strchr(p, '=');
	if (q == NULL) {
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret, "missing = in %s", p);
	    goto out;
	}
	if (q == p) {
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret,
				   "missing name before = in %s", p);
	    goto out;
	}

	if ((size_t)(q - p) > len) {
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret, " = after , in %s", p);
	    goto out;
	}

	ret = stringtooid(p, q - p, &oid);
	if (ret) {
	    ret = HX509_PARSING_NAME_FAILED;
	    hx509_set_error_string(context, 0, ret,
				   "unknown type: %.*s", (int)(q - p), p);
	    goto out;
	}

	{
	    size_t pstr_len = len - (q - p) - 1;
	    const char *pstr = p + (q - p) + 1;
	    char *r;

	    r = malloc(pstr_len + 1);
	    if (r == NULL) {
		der_free_oid(&oid);
		ret = ENOMEM;
		hx509_set_error_string(context, 0, ret, "out of memory");
		goto out;
	    }
	    memcpy(r, pstr, pstr_len);
	    r[pstr_len] = '\0';

	    ret = _hx509_name_modify(context, &n->der_name, 0, &oid, r);
	    free(r);
	    der_free_oid(&oid);
	    if(ret)
		goto out;
	}
	p += len + last;
    }

    *name = n;

    return 0;
out:
    hx509_name_free(&n);
    return HX509_NAME_MALFORMED;
}

/**
 * Copy a hx509 name object.
 *
 * @param context A hx509 cotext.
 * @param from the name to copy from
 * @param to the name to copy to
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_copy(hx509_context context, const hx509_name from, hx509_name *to)
{
    int ret;

    *to = calloc(1, sizeof(**to));
    if (*to == NULL)
	return ENOMEM;
    ret = copy_Name(&from->der_name, &(*to)->der_name);
    if (ret) {
	free(*to);
	*to = NULL;
	return ENOMEM;
    }
    return 0;
}

/**
 * Convert a hx509_name into a Name.
 *
 * @param from the name to copy from
 * @param to the name to copy to
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_to_Name(const hx509_name from, Name *to)
{
    return copy_Name(&from->der_name, to);
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_normalize(hx509_context context, hx509_name name)
{
    return 0;
}

/**
 * Expands variables in the name using env. Variables are on the form
 * ${name}. Useful when dealing with certificate templates.
 *
 * @param context A hx509 cotext.
 * @param name the name to expand.
 * @param env environment variable to expand.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_expand(hx509_context context,
		  hx509_name name,
		  hx509_env env)
{
    Name *n = &name->der_name;
    size_t i, j;
    int bounds_check = 1;

    if (env == NULL)
	return 0;

    if (n->element != choice_Name_rdnSequence) {
	hx509_set_error_string(context, 0, EINVAL, "RDN not of supported type");
	return EINVAL;
    }

    for (i = 0 ; i < n->u.rdnSequence.len; i++) {
	for (j = 0; j < n->u.rdnSequence.val[i].len; j++) {
	    /** Only UTF8String rdnSequence names are allowed */
	    /*
	      THIS SHOULD REALLY BE:
	      COMP = n->u.rdnSequence.val[i].val[j];
	      normalize COMP to utf8
	      check if there are variables
	        expand variables
	        convert back to orignal format, store in COMP
	      free normalized utf8 string
	    */
	    DirectoryString *ds = &n->u.rdnSequence.val[i].val[j].value;
            heim_oid *type = &n->u.rdnSequence.val[i].val[j].type;
            const char *sval = NULL;
	    char *p, *p2;
            char *s = NULL;
	    struct rk_strpool *strpool = NULL;

            switch (ds->element) {
            case choice_DirectoryString_utf8String:
                sval = ds->u.utf8String;
                break;
            case choice_DirectoryString_teletexString:
                sval = ds->u.utf8String;
                break;
            case choice_DirectoryString_ia5String:
                s = strndup(ds->u.ia5String.data,
                            ds->u.ia5String.length);
                break;
            case choice_DirectoryString_printableString:
                s = strndup(ds->u.printableString.data,
                            ds->u.printableString.length);
                break;
            case choice_DirectoryString_universalString:
                hx509_set_error_string(context, 0, ENOTSUP, "UniversalString not supported");
                return ENOTSUP;
            case choice_DirectoryString_bmpString:
                hx509_set_error_string(context, 0, ENOTSUP, "BMPString not supported");
                return ENOTSUP;
            }
            if (sval == NULL && s == NULL)
                return hx509_enomem(context);
            if (s)
                sval = s;

	    p = strstr(sval, "${");
	    if (p) {
		strpool = rk_strpoolprintf(strpool, "%.*s", (int)(p - sval), sval);
		if (strpool == NULL) {
		    hx509_set_error_string(context, 0, ENOMEM, "out of memory");
                    free(s);
		    return ENOMEM;
		}
	    }

	    while (p != NULL) {
		/* expand variables */
		const char *value;
		p2 = strchr(p, '}');
		if (p2 == NULL) {
		    hx509_set_error_string(context, 0, EINVAL, "missing }");
		    rk_strpoolfree(strpool);
                    free(s);
		    return EINVAL;
		}
		p += 2;
		value = hx509_env_lfind(context, env, p, p2 - p);
		if (value == NULL) {
		    hx509_set_error_string(context, 0, EINVAL,
					   "variable %.*s missing",
					   (int)(p2 - p), p);
		    rk_strpoolfree(strpool);
                    free(s);
		    return EINVAL;
		}
		strpool = rk_strpoolprintf(strpool, "%s", value);
		if (strpool == NULL) {
		    hx509_set_error_string(context, 0, ENOMEM, "out of memory");
                    free(s);
		    return ENOMEM;
		}
		p2++;

		p = strstr(p2, "${");
		if (p)
		    strpool = rk_strpoolprintf(strpool, "%.*s",
					       (int)(p - p2), p2);
		else
		    strpool = rk_strpoolprintf(strpool, "%s", p2);
		if (strpool == NULL) {
		    hx509_set_error_string(context, 0, ENOMEM, "out of memory");
                    free(s);
		    return ENOMEM;
		}
	    }

            free(s);
            s = NULL;

	    if (strpool) {
                size_t max_bytes;

                if ((s = rk_strpoolcollect(strpool)) == NULL) {
                    hx509_set_error_string(context, 0, ENOMEM, "out of memory");
                    return ENOMEM;
                }

                /* Check upper bounds! */
                if ((max_bytes = oidtomaxlen(type)) && strlen(s) > max_bytes)
                    bounds_check = 0;

                switch (ds->element) {
                /* C strings: */
                case choice_DirectoryString_utf8String:
                    free(ds->u.utf8String);
                    ds->u.utf8String = s;
                    break;
                case choice_DirectoryString_teletexString:
                    free(ds->u.teletexString);
                    ds->u.teletexString = s;
                    break;

                /* Length and pointer */
                case choice_DirectoryString_ia5String:
                    free(ds->u.ia5String.data);
                    ds->u.ia5String.data = s;
                    ds->u.ia5String.length = strlen(s);
                    break;
                case choice_DirectoryString_printableString:
                    free(ds->u.printableString.data);
                    ds->u.printableString.data = s;
                    ds->u.printableString.length = strlen(s);
                    break;
                default:
                    break; /* Handled above */
                }
	    }
	}
    }

    if (!bounds_check) {
        hx509_set_error_string(context, 0, HX509_PARSING_NAME_FAILED,
                               "some expanded RDNs are too long");
        return HX509_PARSING_NAME_FAILED;
    }
    return 0;
}

/**
 * Free a hx509 name object, upond return *name will be NULL.
 *
 * @param name a hx509 name object to be freed.
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION void HX509_LIB_CALL
hx509_name_free(hx509_name *name)
{
    free_Name(&(*name)->der_name);
    memset(*name, 0, sizeof(**name));
    free(*name);
    *name = NULL;
}

/**
 * Convert a DER encoded name info a string.
 *
 * @param data data to a DER/BER encoded name
 * @param length length of data
 * @param str the resulting string, is NULL on failure.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_unparse_der_name(const void *data, size_t length, char **str)
{
    Name name;
    int ret;

    *str = NULL;

    ret = decode_Name(data, length, &name, NULL);
    if (ret)
	return ret;
    ret = _hx509_Name_to_string(&name, str);
    free_Name(&name);
    return ret;
}

/**
 * Convert a hx509_name object to DER encoded name.
 *
 * @param name name to concert
 * @param os data to a DER encoded name, free the resulting octet
 * string with hx509_xfree(os->data).
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_binary(const hx509_name name, heim_octet_string *os)
{
    size_t size;
    int ret;

    ASN1_MALLOC_ENCODE(Name, os->data, os->length, &name->der_name, &size, ret);
    if (ret)
	return ret;
    if (os->length != size)
	_hx509_abort("internal ASN.1 encoder error");

    return 0;
}

HX509_LIB_FUNCTION int HX509_LIB_CALL
_hx509_unparse_Name(const Name *aname, char **str)
{
    hx509_name name;
    int ret;

    ret = _hx509_name_from_Name(aname, &name);
    if (ret)
	return ret;

    ret = hx509_name_to_string(name, str);
    hx509_name_free(&name);
    return ret;
}

/**
 * Check if a name is empty.
 *
 * @param name the name to check if its empty/null.
 *
 * @return non zero if the name is empty/null.
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_name_is_null_p(const hx509_name name)
{
    return name->der_name.element == choice_Name_rdnSequence &&
        name->der_name.u.rdnSequence.len == 0;
}

int
_hx509_unparse_PermanentIdentifier(hx509_context context,
                                   struct rk_strpool **strpool,
                                   heim_any *value)
{
    PermanentIdentifier pi;
    size_t len;
    const char *pid = "";
    char *s = NULL;
    int ret;

    ret = decode_PermanentIdentifier(value->data, value->length, &pi, &len);
    if (ret == 0 && pi.assigner &&
        der_print_heim_oid(pi.assigner, '.', &s) != 0)
	ret = hx509_enomem(context);
    if (pi.identifierValue && *pi.identifierValue)
        pid = *pi.identifierValue;
    if (ret == 0 &&
        (*strpool = rk_strpoolprintf(*strpool, "%s:%s", s ? s : "", pid)) == NULL)
        ret = hx509_enomem(context);
    free_PermanentIdentifier(&pi);
    free(s);
    if (ret) {
        rk_strpoolfree(*strpool);
        *strpool = rk_strpoolprintf(NULL,
                                    "<error-decoding-PermanentIdentifier");
        hx509_set_error_string(context, 0, ret,
                               "Failed to decode PermanentIdentifier");
    }
    return ret;
}

int
_hx509_unparse_HardwareModuleName(hx509_context context,
                                  struct rk_strpool **strpool,
                                  heim_any *value)
{
    HardwareModuleName hm;
    size_t len;
    char *s = NULL;
    int ret;

    ret = decode_HardwareModuleName(value->data, value->length, &hm, &len);
    if (ret == 0 && hm.hwSerialNum.length > 256)
        hm.hwSerialNum.length = 256;
    if (ret == 0)
        ret = der_print_heim_oid(&hm.hwType, '.', &s);
    if (ret == 0) {
        *strpool = rk_strpoolprintf(*strpool, "%s:%.*s%s", s,
                                    (int)hm.hwSerialNum.length,
                                    (char *)hm.hwSerialNum.data,
                                    value->length == len ? "" : ", <garbage>");
        if (*strpool == NULL)
            ret = hx509_enomem(context);
    }
    free_HardwareModuleName(&hm);
    free(s);
    if (ret) {
        rk_strpoolfree(*strpool);
        *strpool = rk_strpoolprintf(NULL,
                                    "<error-decoding-HardwareModuleName");
        hx509_set_error_string(context, 0, ret,
                               "Failed to decode HardwareModuleName");
    }
    return ret;
}

/*
 * This necessarily duplicates code from libkrb5, and has to unless we move
 * common code here or to lib/roken for it.  We do have slightly different
 * needs (e.g., we want space quoted, and we want to indicate whether we saw
 * trailing garbage, we have no need for flags, no special realm treatment,
 * etc) than the corresponding code in libkrb5, so for now we duplicate this
 * code.
 *
 * The relevant RFCs here are RFC1964 for the string representation of Kerberos
 * principal names, and RFC4556 for the KRB5PrincipalName ASN.1 type (Kerberos
 * lacks such a type because on the wire the name and realm are sent
 * separately as a form of cheap compression).
 *
 * Note that we cannot handle embedded NULs because of Heimdal's representation
 * of ASN.1 strings as C strings.
 */
int
_hx509_unparse_KRB5PrincipalName(hx509_context context,
                                 struct rk_strpool **strpool,
                                 heim_any *value)
{
    KRB5PrincipalName kn;
    size_t len;
    int ret;

    ret = decode_KRB5PrincipalName(value->data, value->length, &kn, &len);
    if (ret == 0 &&
        (*strpool = _hx509_unparse_kerberos_name(*strpool, &kn)) == NULL)
        ret = hx509_enomem(context);
    free_KRB5PrincipalName(&kn);
    if (ret == 0 && (value->length != len) &&
        (*strpool = rk_strpoolprintf(*strpool, " <garbage>")) == NULL)
        ret = hx509_enomem(context);
    if (ret) {
        rk_strpoolfree(*strpool);
        *strpool = rk_strpoolprintf(NULL,
                                    "<error-decoding-PrincipalName");
        hx509_set_error_string(context, 0, ret,
                               "Failed to decode PermanentIdentifier");
    }
    return ret;
}

struct rk_strpool *
_hx509_unparse_kerberos_name(struct rk_strpool *strpool, KRB5PrincipalName *kn)
{
    static const char comp_quotable_chars[] = " \n\t\b\\/@";
    static const char realm_quotable_chars[] = " \n\t\b\\@";
    const char *s;
    size_t i, k, len, plen;
    int need_slash = 0;

    for (i = 0; i < kn->principalName.name_string.len; i++) {
        s = kn->principalName.name_string.val[i];
        len = strlen(s);

        if (need_slash)
            strpool = rk_strpoolprintf(strpool, "/");
        need_slash = 1;

        for (k = 0; k < len; s += plen, k += plen) {
            char c;

            plen = strcspn(s, comp_quotable_chars);
            if (plen)
                strpool = rk_strpoolprintf(strpool, "%.*s", (int)plen, s);
            if (k + plen >= len)
                continue;
            switch ((c = s[plen++])) {
            case '\n':  strpool = rk_strpoolprintf(strpool, "\\n");     break;
            case '\t':  strpool = rk_strpoolprintf(strpool, "\\t");     break;
            case '\b':  strpool = rk_strpoolprintf(strpool, "\\b");     break;
                        /* default -> '@', ' ', '\\', or '/' */
            default:    strpool = rk_strpoolprintf(strpool, "\\%c", c); break;
            }
        }
    }
    if (!kn->realm)
        return strpool;
    strpool = rk_strpoolprintf(strpool, "@");

    s = kn->realm;
    len = strlen(kn->realm);
    for (k = 0; k < len; s += plen, k += plen) {
        char c;

        plen = strcspn(s, realm_quotable_chars);
        if (plen)
            strpool = rk_strpoolprintf(strpool, "%.*s", (int)plen, s);
        if (k + plen >= len)
            continue;
        switch ((c = s[plen++])) {
        case '\n':  strpool = rk_strpoolprintf(strpool, "\\n");     break;
        case '\t':  strpool = rk_strpoolprintf(strpool, "\\t");     break;
        case '\b':  strpool = rk_strpoolprintf(strpool, "\\b");     break;
                    /* default -> '@', ' ', or '\\' */
        default:    strpool = rk_strpoolprintf(strpool, "\\%c", c); break;
        }
    }
    return strpool;
}

int
_hx509_unparse_utf8_string_name(hx509_context context,
                                struct rk_strpool **strpool,
                                heim_any *value)
{
    PKIXXmppAddr us;
    size_t size;
    int ret;

    ret = decode_PKIXXmppAddr(value->data, value->length, &us, &size);
    if (ret == 0 &&
        (*strpool = rk_strpoolprintf(*strpool, "%s", us)) == NULL)
        ret = hx509_enomem(context);
    if (ret) {
        rk_strpoolfree(*strpool);
        *strpool = rk_strpoolprintf(NULL,
                                    "<error-decoding-UTF8String-SAN>");
        hx509_set_error_string(context, 0, ret,
                               "Failed to decode UTF8String SAN");
    }
    free_PKIXXmppAddr(&us);
    return ret;
}

int
_hx509_unparse_ia5_string_name(hx509_context context,
                               struct rk_strpool **strpool,
                               heim_any *value)
{
    SRVName us;
    size_t size;
    int ret;

    ret = decode_SRVName(value->data, value->length, &us, &size);
    if (ret == 0) {
        rk_strpoolfree(*strpool);
        *strpool = rk_strpoolprintf(NULL,
                                    "<error-decoding-IA5String-SAN>");
        hx509_set_error_string(context, 0, ret,
                               "Failed to decode UTF8String SAN");
        return ret;
    }
    *strpool = rk_strpoolprintf(*strpool, "%.*s",
                                (int)us.length, (char *)us.data);
    free_SRVName(&us);
    return ret;
}

typedef int (*other_unparser_f)(hx509_context,
                                struct rk_strpool **,
                                heim_any *);

struct {
    const heim_oid *oid;
    const char *friendly_name;
    other_unparser_f f;
} o_unparsers[] = {
    { &asn1_oid_id_pkinit_san,
        "KerberosPrincipalName",
        _hx509_unparse_KRB5PrincipalName },
    { &asn1_oid_id_pkix_on_permanentIdentifier,
        "PermanentIdentifier",
        _hx509_unparse_PermanentIdentifier },
    { &asn1_oid_id_on_hardwareModuleName,
        "HardwareModuleName",
        _hx509_unparse_HardwareModuleName },
    { &asn1_oid_id_pkix_on_xmppAddr,
        "XMPPName",
        _hx509_unparse_utf8_string_name },
    { &asn1_oid_id_pkinit_ms_san,
        "MSFTKerberosPrincipalName",
        _hx509_unparse_utf8_string_name },
    { &asn1_oid_id_pkix_on_dnsSRV,
        "SRVName",
        _hx509_unparse_ia5_string_name },
};

/**
 * Unparse the hx509 name in name into a string.
 *
 * @param name the name to print
 * @param str an allocated string returns the name in string form
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_general_name_unparse(GeneralName *name, char **str)
{
    hx509_context context;
    int ret;

    if ((ret = hx509_context_init(&context)))
        return ret;
    ret = hx509_general_name_unparse2(context, name, str);
    hx509_context_free(&context);
    return ret;
}

/**
 * Unparse the hx509 name in name into a string.
 *
 * @param context hx509 library context
 * @param name the name to print
 * @param str an allocated string returns the name in string form
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

HX509_LIB_FUNCTION int HX509_LIB_CALL
hx509_general_name_unparse2(hx509_context context,
                            GeneralName *name,
                            char **str)
{
    struct rk_strpool *strpool = NULL;
    int ret = 0;

    *str = NULL;

    switch (name->element) {
    case choice_GeneralName_otherName: {
        size_t i;
	char *oid;

	ret = hx509_oid_sprint(&name->u.otherName.type_id, &oid);
        if (ret == 0)
            strpool = rk_strpoolprintf(strpool, "otherName: %s ", oid);
        if (strpool == NULL)
            ret = ENOMEM;

        for (i = 0; ret == 0 && i < sizeof(o_unparsers)/sizeof(o_unparsers[0]); i++) {
            if (der_heim_oid_cmp(&name->u.otherName.type_id,
                                 o_unparsers[i].oid))
                continue;
            strpool = rk_strpoolprintf(strpool, "%s ",o_unparsers[i].friendly_name);
            if (strpool == NULL)
                ret = ENOMEM;
            if (ret == 0)
                ret = o_unparsers[i].f(context, &strpool, &name->u.otherName.value);
            break;
        }
        if (ret == 0 && i == sizeof(o_unparsers)/sizeof(o_unparsers[0])) {
            strpool = rk_strpoolprintf(strpool, "<unknown-other-name-type>");
            ret = ENOTSUP;
        }
	free(oid);
	break;
    }
    case choice_GeneralName_rfc822Name:
	strpool = rk_strpoolprintf(strpool, "rfc822Name: %.*s",
				   (int)name->u.rfc822Name.length,
				   (char *)name->u.rfc822Name.data);
	break;
    case choice_GeneralName_dNSName:
	strpool = rk_strpoolprintf(strpool, "dNSName: %.*s",
				   (int)name->u.dNSName.length,
				   (char *)name->u.dNSName.data);
	break;
    case choice_GeneralName_directoryName: {
	Name dir;
	char *s;
	memset(&dir, 0, sizeof(dir));
	dir.element = (enum Name_enum)name->u.directoryName.element;
	dir.u.rdnSequence = name->u.directoryName.u.rdnSequence;
	ret = _hx509_unparse_Name(&dir, &s);
	if (ret)
	    return ret;
	strpool = rk_strpoolprintf(strpool, "directoryName: %s", s);
	free(s);
	break;
    }
    case choice_GeneralName_uniformResourceIdentifier:
	strpool = rk_strpoolprintf(strpool, "URI: %.*s",
				   (int)name->u.uniformResourceIdentifier.length,
				   (char *)name->u.uniformResourceIdentifier.data);
	break;
    case choice_GeneralName_iPAddress: {
	unsigned char *a = name->u.iPAddress.data;

	strpool = rk_strpoolprintf(strpool, "IPAddress: ");
	if (strpool == NULL)
	    break;
	if (name->u.iPAddress.length == 4)
	    strpool = rk_strpoolprintf(strpool, "%d.%d.%d.%d",
				       a[0], a[1], a[2], a[3]);
	else if (name->u.iPAddress.length == 16)
	    strpool = rk_strpoolprintf(strpool,
				       "%02X:%02X:%02X:%02X:"
				       "%02X:%02X:%02X:%02X:"
				       "%02X:%02X:%02X:%02X:"
				       "%02X:%02X:%02X:%02X",
				       a[0], a[1], a[2], a[3],
				       a[4], a[5], a[6], a[7],
				       a[8], a[9], a[10], a[11],
				       a[12], a[13], a[14], a[15]);
	else
	    strpool = rk_strpoolprintf(strpool,
				       "unknown IP address of length %lu",
				       (unsigned long)name->u.iPAddress.length);
	break;
    }
    case choice_GeneralName_registeredID: {
	char *oid;
	hx509_oid_sprint(&name->u.registeredID, &oid);
	if (oid == NULL)
	    return ENOMEM;
	strpool = rk_strpoolprintf(strpool, "registeredID: %s", oid);
	free(oid);
	break;
    }
    default:
	return EINVAL;
    }
    if (ret)
        rk_strpoolfree(strpool);
    else if (strpool == NULL || (*str = rk_strpoolcollect(strpool)) == NULL)
	return ENOMEM;
    return ret;
}
