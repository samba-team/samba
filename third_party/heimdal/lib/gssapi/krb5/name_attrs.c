/*
 * Copyright (c) 2021 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

/*
 * (Not-yet-)Standard name attributes for Kerberos MNs,
 * GSS_KRB5_NAME_ATTRIBUTE_BASE_URN + "...".
 *
 * I.e., "urn:ietf:kerberos:nameattr-...".  (XXX Register this URN namespace
 * with IANA.)
 *
 * Note that we do use URN fragments.
 *
 * Specific attributes below the base URN:
 *
 *  - name access attributes:
 *     - "realm"                    -> realm of name
 *     - "name-ncomp"               -> count of name components
 *     - "name-ncomp#<digit>"       -> name component N (0 <= N <= 9)
 *
 * Ticket and Authenticator access attributes:
 *
 *  - "transit-path"                -> encoding of the transited path
 *  - "authenticator-authz-data"    -> encoding of all of the authz-data from
 *                                     the AP-REQ's Authenticator
 *  - "ticket-authz-data"           -> encoding of all of the authz-data from
 *                                     the AP-REQ's Ticket
 *  - "ticket-authz-data#pac"       -> the PAC
 *  - "authz-data#<N>"              -> encoding of all of a specific auth-data
 *                                     element type N (e.g., 2, meaning
 *                                     AD-INTENDED-FOR-SERVER)
 *
 * Misc. attributes:
 *
 *  - "peer-realm"                  -> name of peer's realm (if this is an MN
 *                                     resulting for establishing a security
 *                                     context)
 *  - "canonical-name"              -> exported name token and RFC1964 display
 *                                     syntax of the name's canonical name
 *
 * Compatibility with MIT:
 *
 *  - "urn:mspac:"                  -> the PAC and its individual info buffers
 *
 * TODO:
 *
 *  - Add some sort of display syntax for transit path
 *  - Add support for URN q-components or attribute prefixes to specify
 *    alternative raw and/or display value encodings (JSON?)
 *  - Add support for attributes for accessing other parts of the Ticket / KDC
 *    reply enc-parts, like auth times
 *  - Add support for getting PAC logon fields, including SIDs (one at a time)
 *  - Add support for CAMMAC?
 */

static int
attr_eq(gss_const_buffer_t attr, const char *aname, size_t aname_len, \
	int prefix_check)
{
    if (attr->length < aname_len)
        return 0;

    if (strncmp((char *)attr->value, aname, aname_len) != 0)
	return 0;

    return prefix_check || attr->length == aname_len;
}

#define ATTR_EQ(a, an) (attr_eq(a, an, sizeof(an) - 1, FALSE))
#define ATTR_EQ_PREFIX(a, an) (attr_eq(a, an, sizeof(an) - 1, TRUE))

/* Split attribute into prefix, suffix, and fragment.  See RFC6680. */
static void
split_attr(gss_const_buffer_t orig,
           gss_buffer_t prefix,
           gss_buffer_t attr,
           gss_buffer_t frag,
           int *is_urn)
{
    char *last = NULL;
    char *p = orig->value;

    *attr = *orig;
    prefix->value = orig->value;
    prefix->length = 0;
    frag->length = 0;
    frag->value = NULL;

    /* FIXME We don't have a memrchr() in lib/roken */
    for (p = memchr(p, ' ', orig->length);
         p;
         p = memchr(p + 1, ' ', orig->length)) {
        last = p;
        prefix->length = last - (const char *)orig->value;
        attr->value = last + 1;
        attr->length = orig->length - (prefix->length + 1);
    }
    if (prefix->length == 0)
        prefix->value = NULL;

    if ((*is_urn = (strncmp(attr->value, "urn:", sizeof("urn:") - 1) == 0)) &&
        (p = memchr((char *)attr->value + 1, '#', attr->length - 1))) {
        frag->value = ++p;
        frag->length = attr->length - (p - (const char *)attr->value);
        attr->length = --p - (const char *)attr->value;
    }
}

typedef OM_uint32 get_name_attr_f(OM_uint32 *,
                                  const CompositePrincipal *,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t,
                                  int *,
                                  int *,
                                  gss_buffer_t,
                                  gss_buffer_t,
                                  int *);

typedef OM_uint32 set_name_attr_f(OM_uint32 *,
                                  CompositePrincipal *,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t,
                                  int,
                                  gss_buffer_t);

typedef OM_uint32 del_name_attr_f(OM_uint32 *,
                                  CompositePrincipal *,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t,
                                  gss_const_buffer_t);
typedef get_name_attr_f *get_name_attr_fp;
typedef set_name_attr_f *set_name_attr_fp;
typedef del_name_attr_f *del_name_attr_fp;

static get_name_attr_f get_realm;
static get_name_attr_f get_ncomps;
static get_name_attr_f get_peer_realm;
static get_name_attr_f get_pac;
static get_name_attr_f get_pac_buffer;
static get_name_attr_f get_authz_data;
static get_name_attr_f get_ticket_authz_data;
static get_name_attr_f get_authenticator_authz_data;
static set_name_attr_f set_authenticator_authz_data;
static get_name_attr_f get_transited;
static get_name_attr_f get_canonical_name;

#define NB(n) \
    GSS_KRB5_NAME_ATTRIBUTE_BASE_URN n, n, \
    sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN n) - 1, \
    sizeof(n) - 1
#define NM(n) \
    "urn:mspac:" n, n, sizeof("urn:mspac:" n) - 1, sizeof(n) - 1

static struct krb5_name_attrs {
    const char *fullname;
    const char *name;
    size_t fullnamelen;
    size_t namelen;
    get_name_attr_fp getter;
    set_name_attr_fp setter;
    del_name_attr_fp deleter;
    unsigned int indicate:1;
    unsigned int is_krb5_name_attr_urn:1;
} name_attrs[] = {
    /* XXX We should sort these so we can binary search them */
    { NB("realm"),          get_realm,      NULL, NULL, 1, 1 },
    { NB("name-ncomp"),     get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#0"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#1"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#2"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#3"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#4"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#5"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#6"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#7"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#8"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("name-ncomp#9"),   get_ncomps,     NULL, NULL, 1, 1 },
    { NB("peer-realm"),     get_peer_realm, NULL, NULL, 1, 1 },
    { NB("ticket-authz-data#pac"), get_pac, NULL, NULL, 1, 1 },
    { NM(""),                   get_pac,    NULL, NULL, 1, 0 },
    { NM("logon-info"),         get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("credentials-info"),   get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("server-checksum"),    get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("privsvr-checksum"),   get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("client-info"),        get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("delegation-info"),    get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("upn-dns-info"),       get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("ticket-checksum"),    get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("attributes-info"),    get_pac_buffer,    NULL, NULL, 1, 0 },
    { NM("requestor-sid"),      get_pac_buffer,    NULL, NULL, 1, 0 },
    { NB("ticket-authz-data#kdc-issued"),
         get_ticket_authz_data, NULL, NULL, 1, 1 },
    { NB("ticket-authz-data"),
         get_ticket_authz_data, NULL, NULL, 1, 1 },
    { NB("authenticator-authz-data"),
         get_authenticator_authz_data,
         set_authenticator_authz_data, NULL, 1, 1 },
    { NB("authz-data"),     get_authz_data,  NULL, NULL, 1, 1 },
    { NB("transit-path"),   get_transited,   NULL, NULL, 1, 1 },
    { NB("canonical-name"), get_canonical_name, NULL, NULL, 1, 1 },
};

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_name_attribute(OM_uint32 *minor_status,
                            gss_name_t name,
                            gss_buffer_t original_attr,
                            int *authenticated,
                            int *complete,
                            gss_buffer_t value,
                            gss_buffer_t display_value,
                            int *more)
{
    gss_buffer_desc prefix, attr, suffix, frag;
    size_t i;
    int is_krb5_name_attr_urn = 0;
    int is_urn = 0;

    *minor_status = 0;
    if (authenticated)
        *authenticated = 0;
    if (complete)
        *complete = 0;
    if (more)
        *more = 0;
    if (value) {
        value->length = 0;
        value->value = NULL;
    }
    if (display_value) {
        display_value->length = 0;
        display_value->value = NULL;
    }

    suffix.value = NULL;
    suffix.length = 0;

    split_attr(original_attr, &prefix, &attr, &frag, &is_urn);

    if (prefix.length || !is_urn)
        return GSS_S_UNAVAILABLE;

    is_krb5_name_attr_urn =
        ATTR_EQ_PREFIX(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN);
    if (is_krb5_name_attr_urn) {
        suffix.value =
            (char *)attr.value + sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1;
        suffix.length = attr.length - (sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1);
    }

    for (i = 0; i < sizeof(name_attrs)/sizeof(name_attrs[0]); i++) {
        if (!name_attrs[i].getter)
            continue;
        if (name_attrs[i].is_krb5_name_attr_urn && is_krb5_name_attr_urn) {
            if (!attr_eq(&suffix, name_attrs[i].name, name_attrs[i].namelen, 0))
                continue;
        } else if (!name_attrs[i].is_krb5_name_attr_urn && !is_krb5_name_attr_urn) {
            if (!attr_eq(&attr, name_attrs[i].fullname, name_attrs[i].fullnamelen, 0))
                continue;
        } else
            continue;

        return name_attrs[i].getter(minor_status,
                                    (const CompositePrincipal *)name,
                                    &prefix, &attr, &frag, authenticated,
                                    complete, value, display_value, more);
    }
    return GSS_S_UNAVAILABLE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_set_name_attribute(OM_uint32 *minor_status,
                            gss_name_t name,
                            int complete,
                            gss_buffer_t original_attr,
                            gss_buffer_t value)
{
    gss_buffer_desc prefix, attr, suffix, frag;
    size_t i;
    int is_krb5_name_attr_urn = 0;
    int is_urn = 0;

    *minor_status = 0;

    suffix.value = NULL;
    suffix.length = 0;

    split_attr(original_attr, &prefix, &attr, &frag, &is_urn);

    if (prefix.length || !is_urn)
        return GSS_S_UNAVAILABLE;

    is_krb5_name_attr_urn =
        ATTR_EQ_PREFIX(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN);
    if (is_krb5_name_attr_urn) {
        suffix.value =
            (char *)attr.value + sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1;
        suffix.length = attr.length - (sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1);
    }

    for (i = 0; i < sizeof(name_attrs)/sizeof(name_attrs[0]); i++) {
        if (!name_attrs[i].setter)
            continue;
        if (name_attrs[i].is_krb5_name_attr_urn && is_krb5_name_attr_urn) {
            if (!attr_eq(&suffix, name_attrs[i].name, name_attrs[i].namelen, 0))
                continue;
        } else if (!name_attrs[i].is_krb5_name_attr_urn && !is_krb5_name_attr_urn) {
            if (!attr_eq(&attr, name_attrs[i].name, name_attrs[i].namelen, 0))
                continue;
        } else
            continue;

        return name_attrs[i].setter(minor_status, (CompositePrincipal *)name,
                                    &prefix, &attr, &frag, complete, value);
    }
    return GSS_S_UNAVAILABLE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_delete_name_attribute(OM_uint32 *minor_status,
                               gss_name_t name,
                               gss_buffer_t original_attr)
{
    gss_buffer_desc prefix, attr, suffix, frag;
    size_t i;
    int is_krb5_name_attr_urn = 0;
    int is_urn = 0;

    *minor_status = 0;

    suffix.value = NULL;
    suffix.length = 0;

    split_attr(original_attr, &prefix, &attr, &frag, &is_urn);

    if (prefix.length || !is_urn)
        return GSS_S_UNAVAILABLE;

    is_krb5_name_attr_urn =
        ATTR_EQ_PREFIX(&attr, GSS_KRB5_NAME_ATTRIBUTE_BASE_URN);
    if (is_krb5_name_attr_urn) {
        suffix.value =
            (char *)attr.value + sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1;
        suffix.length = attr.length - (sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN) - 1);
    }

    for (i = 0; i < sizeof(name_attrs)/sizeof(name_attrs[0]); i++) {
        if (!name_attrs[i].deleter)
            continue;
        if (name_attrs[i].is_krb5_name_attr_urn && is_krb5_name_attr_urn) {
            if (!attr_eq(&suffix, name_attrs[i].name, name_attrs[i].namelen, 0))
                continue;
        } else if (!name_attrs[i].is_krb5_name_attr_urn && !is_krb5_name_attr_urn) {
            if (!attr_eq(&attr, name_attrs[i].fullname, name_attrs[i].fullnamelen, 0))
                continue;
        } else
            continue;

        return name_attrs[i].deleter(minor_status, (CompositePrincipal *)name,
                                    &prefix, &attr, &frag);
    }
    return GSS_S_UNAVAILABLE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_name(OM_uint32 *minor_status,
                      gss_name_t name,
                      int *name_is_MN,
                      gss_OID *MN_mech,
                      gss_buffer_set_t *attrs)
{
    gss_buffer_desc prefix, attr, frag, a;
    OM_uint32 major = GSS_S_UNAVAILABLE;
    size_t i;
    int authenticated, is_urn;

    *minor_status = 0;
    if (name_is_MN)
        *name_is_MN = 1;
    if (MN_mech)
        *MN_mech = GSS_KRB5_MECHANISM;
    if (name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (attrs == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    for (i = 0; i < sizeof(name_attrs)/sizeof(name_attrs[0]); i++) {
        if (!name_attrs[i].indicate)
            continue;
        a.value = (void *)(uintptr_t)name_attrs[i].fullname;
        a.length = name_attrs[i].fullnamelen;
        split_attr(&a, &prefix, &attr, &frag, &is_urn);
        major = name_attrs[i].getter(minor_status,
                                     (const CompositePrincipal *)name,
                                     &prefix, &attr, &frag, &authenticated,
                                     NULL, NULL, NULL, NULL);
        if (major == GSS_S_UNAVAILABLE)
            continue;
        if (major != GSS_S_COMPLETE)
            break;
        major = gss_add_buffer_set_member(minor_status, &a, attrs);
    }
    if (major == GSS_S_UNAVAILABLE)
        major = GSS_S_COMPLETE;
    return major;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_display_name_ext(OM_uint32 *minor_status,
                          gss_name_t name,
                          gss_OID display_as_name_type,
                          gss_buffer_t display_name)
{
    krb5_const_principal p = (void *)name;
    char *s = NULL;

    *minor_status = 0;
    if (display_name == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    display_name->length = 0;
    display_name->value = NULL;

    if (gss_oid_equal(display_as_name_type, GSS_C_NT_USER_NAME)) {
        if (p->name.name_string.len != 1)
            return GSS_S_UNAVAILABLE;
        return _gsskrb5_localname(minor_status, name, GSS_KRB5_MECHANISM,
                                  display_name);
    }
    if (!gss_oid_equal(display_as_name_type, GSS_C_NT_HOSTBASED_SERVICE) ||
        p->name.name_string.len != 2 ||
        strchr(p->name.name_string.val[0], '@') ||
        strchr(p->name.name_string.val[1], '.') == NULL)
        return GSS_S_UNAVAILABLE;
    if (asprintf(&s, "%s@%s", p->name.name_string.val[0],
                 p->name.name_string.val[1]) == -1 || s == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    display_name->length = strlen(s);
    display_name->value = s;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_export_name_composite(OM_uint32 *minor_status,
                               gss_name_t name,
                               gss_buffer_t exported_name)
{
    krb5_error_code kret;
    gss_buffer_desc inner = GSS_C_EMPTY_BUFFER;
    unsigned char *buf;
    size_t sz;

    if (name == NULL)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (exported_name == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    ASN1_MALLOC_ENCODE(CompositePrincipal, inner.value, inner.length,
                       (void *)name, &sz, kret);
    if (kret != 0) {
        *minor_status = kret;
        return GSS_S_FAILURE;
    }

    exported_name->length = 10 + inner.length + GSS_KRB5_MECHANISM->length;
    exported_name->value  = malloc(exported_name->length);
    if (exported_name->value == NULL) {
	free(inner.value);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    /* TOK, MECH_OID_LEN, DER(MECH_OID), NAME_LEN, NAME */

    buf = exported_name->value;
    buf[0] = 0x04;
    buf[1] = 0x02;
    buf[2] = ((GSS_KRB5_MECHANISM->length + 2) >> 8) & 0xff;
    buf[3] = (GSS_KRB5_MECHANISM->length + 2) & 0xff;
    buf[4] = 0x06;
    buf[5] = (GSS_KRB5_MECHANISM->length) & 0xFF;

    memcpy(buf + 6, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
    buf += 6 + GSS_KRB5_MECHANISM->length;

    buf[0] = (inner.length >> 24) & 0xff;
    buf[1] = (inner.length >> 16) & 0xff;
    buf[2] = (inner.length >> 8) & 0xff;
    buf[3] = (inner.length) & 0xff;
    buf += 4;

    memcpy(buf, inner.value, inner.length);
    free(inner.value);

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

#define CHECK_ENOMEM(v, dv) \
    do { \
        if (((v) && !(v)->value) || ((dv) && !(dv)->value)) { \
            if ((v) && (v)->value) { \
                free((v)->value); \
                (v)->length = 0; \
                (v)->value = NULL; \
            } \
            *minor_status = ENOMEM; \
            return GSS_S_FAILURE; \
        } \
    } while (0)

static OM_uint32
get_realm(OM_uint32 *minor_status,
          const CompositePrincipal *name,
          gss_const_buffer_t prefix,
          gss_const_buffer_t attr,
          gss_const_buffer_t frag,
          int *authenticated,
          int *complete,
          gss_buffer_t value,
          gss_buffer_t display_value,
          int *more)
{
    PrincipalNameAttrs *nameattrs = name->nameattrs;

    if (prefix->length || frag->length || !name->realm)
        return GSS_S_UNAVAILABLE;
    if (authenticated && nameattrs && nameattrs->authenticated)
        *authenticated = 1;
    if (complete)
        *complete = 1;
    if (value && (value->value = strdup(name->realm)))
        value->length = strlen(name->realm);
    if (display_value && (display_value->value = strdup(name->realm)))
        display_value->length = strlen(name->realm);
    CHECK_ENOMEM(value, display_value);
    return GSS_S_COMPLETE;
}

static OM_uint32
get_ncomps(OM_uint32 *minor_status,
           const CompositePrincipal *name,
           gss_const_buffer_t prefix,
           gss_const_buffer_t attr,
           gss_const_buffer_t frag,
           int *authenticated,
           int *complete,
           gss_buffer_t value,
           gss_buffer_t display_value,
           int *more)
{
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    int n = -1;

    if (authenticated && nameattrs && nameattrs->authenticated)
        *authenticated = 1;
    if (complete)
        *complete = 1;

    if (frag->length == 1 &&
        ((const char *)frag->value)[0] >= '0' &&
        ((const char *)frag->value)[0] <= '9') {
        n = ((const char *)frag->value)[0] - '0';
    } else if (frag->length == sizeof("all") - 1 &&
               strncmp(frag->value, "all", sizeof("all") - 1) == 0) {
        if (!more || *more < -1 || *more == 0 || *more > CHAR_MAX ||
            *more > (int)name->name.name_string.len) {
            *minor_status = EINVAL;
            return GSS_S_UNAVAILABLE;
        }
        if (*more == -1) {
            *more = name->name.name_string.len - 1;
            n = 0;
        } else {
            n = name->name.name_string.len - *more;
            (*more)--;
        }
    }

    if (frag->length == 0) {
        char *s = NULL;

        /* Outut count of components */
        if (value && (value->value = malloc(sizeof(size_t)))) {
            *((size_t *)value->value) = name->name.name_string.len;
            value->length = sizeof(size_t);
        }
        if (display_value &&
            asprintf(&s, "%u", (unsigned int)name->name.name_string.len) > 0) {
            display_value->value = s;
            display_value->length = strlen(display_value->value);
        }
    } else {
        /*
         * Output a component.  The value and the display value are the same in
         * this case.
         */
        if (n < 0 || n >= name->name.name_string.len) {
            *minor_status = EINVAL;
            return GSS_S_UNAVAILABLE;
        }
        if (value && (value->value = strdup(name->name.name_string.val[n])))
            value->length = strlen(name->name.name_string.val[n]);
        if (display_value &&
            (display_value->value = strdup(name->name.name_string.val[n])))
            display_value->length = strlen(name->name.name_string.val[n]);
    }

    CHECK_ENOMEM(value, display_value);
    return GSS_S_COMPLETE;
}

static OM_uint32
get_peer_realm(OM_uint32 *minor_status,
               const CompositePrincipal *name,
               gss_const_buffer_t prefix,
               gss_const_buffer_t attr,
               gss_const_buffer_t frag,
               int *authenticated,
               int *complete,
               gss_buffer_t value,
               gss_buffer_t display_value,
               int *more)
{
    PrincipalNameAttrs *nameattrs = name->nameattrs;

    if (prefix->length || frag->length || !nameattrs || !nameattrs->peer_realm)
        return GSS_S_UNAVAILABLE;
    if (authenticated)
        *authenticated = 1;
    if (complete)
        *complete = 1;
    if (value && (value->value = strdup(nameattrs->peer_realm[0])))
        value->length = strlen(value->value);
    if (display_value &&
        (display_value->value = strdup(nameattrs->peer_realm[0])))
        display_value->length = strlen(display_value->value);

    CHECK_ENOMEM(value, display_value);
    return GSS_S_COMPLETE;
}

static OM_uint32
get_pac(OM_uint32 *minor_status,
        const CompositePrincipal *name,
        gss_const_buffer_t prefix,
        gss_const_buffer_t attr,
        gss_const_buffer_t frag,
        int *authenticated,
        int *complete,
        gss_buffer_t value,
        gss_buffer_t display_value,
        int *more)
{
    krb5_error_code kret;
    krb5_context context;
    krb5_data data;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    EncTicketPart *ticket = NULL;

    krb5_data_zero(&data);

    if (src == NULL ||
	src->element != choice_PrincipalNameAttrSrc_enc_ticket_part)
	return GSS_S_UNAVAILABLE;

    ticket = &src->u.enc_ticket_part;

    if (prefix->length || !authenticated || !ticket)
        return GSS_S_UNAVAILABLE;

    GSSAPI_KRB5_INIT(&context);

    *authenticated = nameattrs->pac_verified;
    if (complete)
        *complete = 1;

    kret = _krb5_get_ad(context, ticket->authorization_data,
                        NULL, KRB5_AUTHDATA_WIN2K_PAC,
                        value ? &data : NULL);

    if (value) {
	value->length = data.length;
	value->value = data.data;
    }

    *minor_status = kret;
    if (kret == ENOENT)
        return GSS_S_UNAVAILABLE;
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_pac_buffer(OM_uint32 *minor_status,
	       const CompositePrincipal *name,
	       gss_const_buffer_t prefix,
	       gss_const_buffer_t attr,
	       gss_const_buffer_t frag,
	       int *authenticated,
	       int *complete,
	       gss_buffer_t value,
	       gss_buffer_t display_value,
	       int *more)
{
    krb5_error_code kret;
    krb5_context context;
    krb5_data data;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    krb5_data suffix;

    krb5_data_zero(&data);

    if (prefix->length || !authenticated ||
	!nameattrs || !nameattrs->pac)
        return GSS_S_UNAVAILABLE;

    GSSAPI_KRB5_INIT(&context);

    if (ATTR_EQ_PREFIX(attr, "urn:mspac:")) {
        suffix.length = attr->length - (sizeof("urn:mspac:") - 1);
        suffix.data = (char *)attr->value + sizeof("urn:mspac:") - 1;
    } else if (ATTR_EQ_PREFIX(frag, "pac-")) {
        suffix.length = frag->length - sizeof("pac-") - 1;
        suffix.data = (char *)frag->value + sizeof("pac-") - 1;
    } else
        return GSS_S_UNAVAILABLE; /* should not be reached */

    *authenticated = nameattrs->pac_verified;
    if (complete)
        *complete = 1;

    kret = _krb5_pac_get_buffer_by_name(context, nameattrs->pac, &suffix,
					value ? &data : NULL);

    if (value) {
	value->length = data.length;
	value->value = data.data;
    }

    *minor_status = kret;
    if (kret == ENOENT)
        return GSS_S_UNAVAILABLE;
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_authz_data(OM_uint32 *minor_status,
               const CompositePrincipal *name,
               gss_const_buffer_t prefix,
               gss_const_buffer_t attr,
               gss_const_buffer_t frag,
               int *authenticated,
               int *complete,
               gss_buffer_t value,
               gss_buffer_t display_value,
               int *more)
{
    krb5_error_code kret = 0;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    EncTicketPart *ticket = NULL;
    krb5_context context;
    krb5_data data;
    char s[22];
    char *end;
    int64_t n;

    if (src) switch (src->element) {
    case choice_PrincipalNameAttrSrc_enc_ticket_part:
        ticket = &src->u.enc_ticket_part;
        break;
    case choice_PrincipalNameAttrSrc_enc_kdc_rep_part:
    default:
        return GSS_S_UNAVAILABLE;
    }

    if (!nameattrs || !frag->length || frag->length > sizeof(s) - 1)
        return GSS_S_UNAVAILABLE;

    /* Output a specific AD element from the ticket or authenticator */
    krb5_data_zero(&data);
    memcpy(s, frag->value, frag->length);
    s[frag->length] = '\0';
    errno = 0;
    n = strtoll(s, &end, 10);
    if (end[0] == '\0' && (errno || n > INT_MAX || n < INT_MIN)) {
        *minor_status = ERANGE;
        return GSS_S_UNAVAILABLE;
    }
    if (end[0] != '\0') {
        *minor_status = EINVAL;
        return GSS_S_UNAVAILABLE;
    }

    if (authenticated)
        *authenticated = 0;
    if (complete)
        *complete = 1;

    GSSAPI_KRB5_INIT(&context);

    kret = ENOENT;
    if (ticket && ticket->authorization_data) {
        kret = _krb5_get_ad(context, ticket->authorization_data,
                            NULL, n, value ? &data : NULL);

        /* If it's from the ticket, it _may_ be authenticated: */
        if (kret == 0 && authenticated) {
            if (n == KRB5_AUTHDATA_KDC_ISSUED)
                *authenticated = nameattrs->kdc_issued_verified;
            else if (n == KRB5_AUTHDATA_WIN2K_PAC)
                *authenticated = nameattrs->pac_verified;
        }
    }
    if (kret == ENOENT && nameattrs->authenticator_ad &&
        n != KRB5_AUTHDATA_KDC_ISSUED &&
        n != KRB5_AUTHDATA_WIN2K_PAC) {
        kret = _krb5_get_ad(context, nameattrs->authenticator_ad,
                            NULL, n, value ? &data : NULL);
    }

    if (value) {
        value->length = data.length;
        value->value = data.data;
    }
    *minor_status = kret;
    if (kret == ENOENT)
        return GSS_S_UNAVAILABLE;
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_ticket_authz_data(OM_uint32 *minor_status,
                      const CompositePrincipal *name,
                      gss_const_buffer_t prefix,
                      gss_const_buffer_t attr,
                      gss_const_buffer_t frag,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more)
{
    krb5_error_code kret = 0;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    EncTicketPart *ticket = NULL;
    size_t sz;

    if (src) switch (src->element) {
    case choice_PrincipalNameAttrSrc_enc_ticket_part:
        ticket = &src->u.enc_ticket_part;
        break;
    case choice_PrincipalNameAttrSrc_enc_kdc_rep_part:
    default:
        return GSS_S_UNAVAILABLE;
    }

    if (!ticket)
        return GSS_S_UNAVAILABLE;

    if (complete)
        *complete = 1;

    if (frag->length == sizeof("kdc-issued") - 1 &&
        strncmp(frag->value, "kdc-issued", sizeof("kdc-issued") - 1) == 0) {
        krb5_context context;
        krb5_data data;

        GSSAPI_KRB5_INIT(&context);
        if (authenticated)
            *authenticated = nameattrs->kdc_issued_verified;

        kret = _krb5_get_ad(context, ticket->authorization_data,
                            NULL, KRB5_AUTHDATA_KDC_ISSUED,
                            value ? &data : NULL);
        if (value) {
            value->length = data.length;
            value->value = data.data;
        }
        if (kret == ENOENT)
            return GSS_S_UNAVAILABLE;
        *minor_status = kret;
        return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
    } else if (frag->length) {
        return GSS_S_UNAVAILABLE;
    }

    /* Just because it's in the Ticket doesn't make it authenticated */
    if (authenticated)
        *authenticated = 0;

    if (value) {
        ASN1_MALLOC_ENCODE(AuthorizationData, value->value, value->length,
                           ticket->authorization_data, &sz, kret);
        *minor_status = kret;
    }
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_authenticator_authz_data(OM_uint32 *minor_status,
                             const CompositePrincipal *name,
                             gss_const_buffer_t prefix,
                             gss_const_buffer_t attr,
                             gss_const_buffer_t frag,
                             int *authenticated,
                             int *complete,
                             gss_buffer_t value,
                             gss_buffer_t display_value,
                             int *more)
{
    krb5_error_code kret = 0;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    size_t sz;

    if (!nameattrs || !nameattrs->authenticator_ad)
        return GSS_S_UNAVAILABLE;
    if (authenticated)
        *authenticated = 0;
    if (complete)
        *complete = 1;

    if (value) {
        ASN1_MALLOC_ENCODE(AuthorizationData, value->value, value->length,
                           nameattrs->authenticator_ad, &sz, kret);
        *minor_status = kret;
    }
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
set_authenticator_authz_data(OM_uint32 *minor_status,
                             CompositePrincipal *name,
                             gss_const_buffer_t prefix,
                             gss_const_buffer_t attr,
                             gss_const_buffer_t frag,
                             int complete,
                             gss_buffer_t value)
{
    AuthorizationDataElement e;
    krb5_error_code kret;
    size_t sz;

    if (!value)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (frag->length &&
        !ATTR_EQ(frag, "if-relevant"))
        return GSS_S_UNAVAILABLE;

    if ((name->nameattrs == NULL &&
        (name->nameattrs = calloc(1, sizeof(*name->nameattrs))) == NULL) ||
        (name->nameattrs->want_ad == NULL &&
         (name->nameattrs->want_ad =
          calloc(1, sizeof(*name->nameattrs->want_ad))) == NULL)) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    memset(&e, 0, sizeof(e));
    kret = decode_AuthorizationDataElement(value->value, value->length, &e,
                                           &sz);
    if (kret == 0) {
        if (frag->length) {
            AuthorizationData ir;

            ir.len = 0;
            ir.val = NULL;
            kret = add_AuthorizationData(&ir, &e);
            free_AuthorizationDataElement(&e);
            if (kret == 0) {
                e.ad_type = KRB5_AUTHDATA_IF_RELEVANT;
                ASN1_MALLOC_ENCODE(AuthorizationData, e.ad_data.data,
                                   e.ad_data.length, &ir, &sz, kret);
                kret = add_AuthorizationData(name->nameattrs->want_ad, &e);
            }
            free_AuthorizationData(&ir);
        } else {
            kret = add_AuthorizationData(name->nameattrs->want_ad, &e);
            free_AuthorizationDataElement(&e);
        }
    }

    *minor_status = kret;
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_transited(OM_uint32 *minor_status,
              const CompositePrincipal *name,
              gss_const_buffer_t prefix,
              gss_const_buffer_t attr,
              gss_const_buffer_t frag,
              int *authenticated,
              int *complete,
              gss_buffer_t value,
              gss_buffer_t display_value,
              int *more)
{
    krb5_error_code kret = 0;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    EncTicketPart *ticket = NULL;
    size_t sz;

    if (src) switch (src->element) {
    case choice_PrincipalNameAttrSrc_enc_kdc_rep_part:
        break;
    case choice_PrincipalNameAttrSrc_enc_ticket_part:
        ticket = &src->u.enc_ticket_part;
        break;
    default:
        return GSS_S_UNAVAILABLE;
    }

    if (!nameattrs && !ticket)
        return GSS_S_UNAVAILABLE;
    if (nameattrs && !nameattrs->transited && !ticket)
        return GSS_S_UNAVAILABLE;

    if (authenticated)
        *authenticated = 1;
    if (complete)
        *complete = 1;

    if (value && ticket)
        ASN1_MALLOC_ENCODE(TransitedEncoding, value->value, value->length,
                           &ticket->transited, &sz, kret);
    else if (value && nameattrs->transited)
        ASN1_MALLOC_ENCODE(TransitedEncoding, value->value, value->length,
                           nameattrs->transited, &sz, kret);
    *minor_status = kret;
    return kret == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
get_canonical_name(OM_uint32 *minor_status,
                   const CompositePrincipal *name,
                   gss_const_buffer_t prefix,
                   gss_const_buffer_t attr,
                   gss_const_buffer_t frag,
                   int *authenticated,
                   int *complete,
                   gss_buffer_t value,
                   gss_buffer_t display_value,
                   int *more)
{
    krb5_error_code kret = 0;
    PrincipalNameAttrs *nameattrs = name->nameattrs;
    PrincipalNameAttrSrc *src = nameattrs ? nameattrs->source : NULL;
    krb5_principal p = NULL;
    krb5_context context;
    EncTicketPart *ticket = NULL;
    EncKDCRepPart *kdcrep = NULL;

    if (src) switch (src->element) {
    case choice_PrincipalNameAttrSrc_enc_kdc_rep_part:
        kdcrep = &src->u.enc_kdc_rep_part;
        break;
    case choice_PrincipalNameAttrSrc_enc_ticket_part:
        ticket = &src->u.enc_ticket_part;
        break;
    default:
        return GSS_S_UNAVAILABLE;
    }

    GSSAPI_KRB5_INIT(&context);

    if (authenticated)
        *authenticated = 1;
    if (complete)
        *complete = 1;

    if (kdcrep) {
        kret = _krb5_principalname2krb5_principal(context, &p,
                                                  kdcrep->sname,
                                                  kdcrep->srealm);
    } else if (nameattrs && nameattrs->pac &&
	(_krb5_pac_get_canon_principal(context, nameattrs->pac, &p)) == 0) {
	if (authenticated)
	    *authenticated = nameattrs->pac_verified;
    } else if (ticket) {
        krb5_data data;
        krb5_pac pac = NULL;

        krb5_data_zero(&data);

        /* Use canonical name from PAC if available */
        kret = _krb5_get_ad(context, ticket->authorization_data,
                            NULL, KRB5_AUTHDATA_WIN2K_PAC, &data);
        if (kret == 0)
            kret = krb5_pac_parse(context, data.data, data.length, &pac);
        if (kret == 0)
            kret = _krb5_pac_get_canon_principal(context, pac, &p);
        if (kret == 0 && authenticated)
            *authenticated = nameattrs->pac_verified;
        else if (kret == ENOENT)
            kret = _krb5_principalname2krb5_principal(context, &p,
                                                      ticket->cname,
                                                      ticket->crealm);

        krb5_data_free(&data);
        krb5_pac_free(context, pac);
    } else
        return GSS_S_UNAVAILABLE;
    if (kret == 0 && value) {
        OM_uint32 major;
        /*
         * Value is exported name token (exported composite name token
         * should also work).
         */
        major = _gsskrb5_export_name(minor_status, (gss_name_t)p, value);
        if (major != GSS_S_COMPLETE) {
            krb5_free_principal(context, p);
            return major;
        }
    }
    if (kret == 0 && display_value) {
        /* Display value is principal name display form */
        kret = krb5_unparse_name(context, p,
                                 (char **)&display_value->value);
        if (kret == 0)
            display_value->length = strlen(display_value->value);
    }

    krb5_free_principal(context, p);
    if (kret) {
        if (value) {
            free(value->value);
            value->length = 0;
            value->value = NULL;
        }
        *minor_status = kret;
        return GSS_S_UNAVAILABLE;
    }
    return GSS_S_COMPLETE;
}
