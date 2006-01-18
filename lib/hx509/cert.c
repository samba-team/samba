/*
 * Copyright (c) 2004 - 2005 Kungliga Tekniska Högskolan
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
RCSID("$Id$");
#include "crypto-headers.h"


struct hx509_verify_ctx_data {
    hx509_certs trust_anchors;
    int flags;
#define HX509_VERIFY_CTX_F_TIME_SET			1
#define HX509_VERIFY_CTX_F_ALLOW_PROXY_CERTIFICATE	2
    time_t time_now;
    int max_depth;
#define HX509_VERIFY_MAX_DEPTH 30
    hx509_revoke_ctx revoke_ctx;
};

struct _hx509_cert_attrs {
    size_t len;
    hx509_cert_attribute *val;
};

struct hx509_cert_data {
    unsigned int ref;
    char *friendlyname;
    Certificate *data;
    hx509_private_key private_key;
    struct _hx509_cert_attrs attrs;
};

typedef struct hx509_name_constraints {
    /* NameConstraints nc; */
    struct {
	GeneralSubtrees *permittedSubtrees;
	GeneralSubtrees *excludedSubtrees;
    } nc;
} hx509_name_constraints;

#define GeneralSubtrees_SET(g,var) \
	(g)->len = (var)->len, (g)->val = (var)->val;

/*
 *
 */

void
_hx509_abort(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
    abort();
}

/*
 *
 */

int
hx509_context_init(hx509_context *context)
{
    *context = calloc(1, sizeof(**context));
    if (*context == NULL)
	return ENOMEM;

    _hx509_ks_mem_register(*context);
    _hx509_ks_file_register(*context);
    _hx509_ks_pkcs12_register(*context);
    _hx509_ks_pkcs11_register(*context);
    _hx509_ks_dir_register(*context);

    ENGINE_add_conf_module();

    return 0;
}

void
hx509_context_free(hx509_context *context)
{
    if ((*context)->ks_ops) {
	free((*context)->ks_ops);
	(*context)->ks_ops = NULL;
    }
    (*context)->ks_num_ops = 0;
    free(*context);
    *context = NULL;
}


/*
 *
 */

Certificate *
_hx509_get_cert(hx509_cert cert)
{
    return cert->data;
}

int
_hx509_cert_get_version(const Certificate *t)
{
    return t->tbsCertificate.version ? *t->tbsCertificate.version + 1 : 1;
}

int
hx509_cert_init(hx509_context context, const Certificate *c, hx509_cert *cert)
{
    int ret;

    *cert = malloc(sizeof(**cert));
    if (*cert == NULL)
	return ENOMEM;
    (*cert)->ref = 1;
    (*cert)->friendlyname = NULL;
    (*cert)->attrs.len = 0;
    (*cert)->attrs.val = NULL;
    (*cert)->private_key = NULL;

    (*cert)->data = malloc(sizeof(*(*cert)->data));
    if ((*cert)->data == NULL) {
	free(*cert);
	return ENOMEM;
    }
    memset((*cert)->data, 0, sizeof(*(*cert)->data));
    ret = copy_Certificate(c, (*cert)->data);
    if (ret) {
	free((*cert)->data);
	free(*cert);
    }
    return ret;
}

int
_hx509_cert_assign_private_key_file(hx509_cert cert, 
				    hx509_lock lock,
				    const char *fn)
{
    int ret;
    if (cert->private_key == NULL) {
	ret = _hx509_new_private_key(&cert->private_key);
	if (ret)
	    return ret;
    }
    ret = _hx509_private_key_assign_key_file(cert->private_key, lock, fn);
    if (ret)
	_hx509_free_private_key(&cert->private_key);
    return ret;
}

/* Doesn't make a copy of `private_key'. */

int
_hx509_cert_assign_key(hx509_cert cert, hx509_private_key private_key)
{
    if (cert->private_key)
	_hx509_free_private_key(&cert->private_key);
    cert->private_key = private_key;
    return 0;
}

void
hx509_cert_free(hx509_cert cert)
{
    int i;

    if (cert->ref <= 0)
	_hx509_abort("refcount <= 0");
    if (--cert->ref > 0)
	return;

    if (cert->private_key)
	_hx509_free_private_key(&cert->private_key);

    free_Certificate(cert->data);
    free(cert->data);

    for (i = 0; i < cert->attrs.len; i++) {
	free_octet_string(&cert->attrs.val[i]->data);
	free_oid(&cert->attrs.val[i]->oid);
	free(cert->attrs.val[i]);
    }
    free(cert->attrs.val);
    free(cert->friendlyname);
    memset(cert, 0, sizeof(cert));
    free(cert);
}

hx509_cert
hx509_cert_ref(hx509_cert cert)
{
    if (cert->ref <= 0)
	_hx509_abort("refcount <= 0");
    cert->ref++;
    if (cert->ref == 0)
	_hx509_abort("refcount == 0");
    return cert;
}

int
hx509_verify_init_ctx(hx509_context context, hx509_verify_ctx *ctx)
{
    hx509_verify_ctx c;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
	return ENOMEM;

    c->max_depth = HX509_VERIFY_MAX_DEPTH;

    *ctx = c;
    
    return 0;
}

void
hx509_verify_destroy_ctx(hx509_verify_ctx ctx)
{
    if (ctx->trust_anchors)
	hx509_certs_free(&ctx->trust_anchors);
    if (ctx->revoke_ctx)
	hx509_revoke_free(&ctx->revoke_ctx);

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

void
hx509_verify_attach_anchors(hx509_verify_ctx ctx, hx509_certs set)
{
    if (ctx->trust_anchors)
	hx509_certs_free(&ctx->trust_anchors);
    ctx->trust_anchors = set;
}

void
hx509_verify_attach_revoke(hx509_verify_ctx ctx, hx509_revoke_ctx revoke)
{
    if (ctx->revoke_ctx)
	hx509_revoke_free(&ctx->revoke_ctx);
    ctx->revoke_ctx = revoke;
}

void
hx509_verify_set_time(hx509_verify_ctx ctx, time_t t)
{
    ctx->flags |= HX509_VERIFY_CTX_F_TIME_SET;
    ctx->time_now = t;
}

static const Extension *
find_extension(const Certificate *cert, const heim_oid *oid, int *idx)
{
    const TBSCertificate *c = &cert->tbsCertificate;

    if (c->version == NULL || *c->version < 2 || c->extensions == NULL)
	return NULL;
    
    for (;*idx < c->extensions->len; (*idx)++) {
	if (heim_oid_cmp(&c->extensions->val[*idx].extnID, oid) == 0)
	    return &c->extensions->val[*idx];
    }
    return NULL;
}

static int
find_extension_auth_key_id(const Certificate *subject, 
			   AuthorityKeyIdentifier *ai)
{
    const Extension *e;
    size_t size;
    int i = 0;

    memset(ai, 0, sizeof(*ai));

    e = find_extension(subject, oid_id_x509_ce_authorityKeyIdentifier(), &i);
    if (e == NULL)
	return HX509_EXTENSION_NOT_FOUND;
    
    return decode_AuthorityKeyIdentifier(e->extnValue.data, 
					 e->extnValue.length, 
					 ai, &size);
}

static int
find_extension_subject_key_id(const Certificate *issuer,
			      SubjectKeyIdentifier *si)
{
    const Extension *e;
    size_t size;
    int i = 0;

    memset(si, 0, sizeof(*si));

    e = find_extension(issuer, oid_id_x509_ce_subjectKeyIdentifier(), &i);
    if (e == NULL)
	return HX509_EXTENSION_NOT_FOUND;
    
    return decode_SubjectKeyIdentifier(e->extnValue.data, 
				       e->extnValue.length,
				       si, &size);
}

static int
find_extension_name_constraints(const Certificate *subject, 
				NameConstraints *nc)
{
    const Extension *e;
    size_t size;
    int i = 0;

    memset(nc, 0, sizeof(*nc));

    e = find_extension(subject, oid_id_x509_ce_nameConstraints(), &i);
    if (e == NULL)
	return HX509_EXTENSION_NOT_FOUND;
    
    return decode_NameConstraints(e->extnValue.data, 
				  e->extnValue.length, 
				  nc, &size);
}

static int
find_extension_subject_alt_name(const Certificate *cert, int *i,
				GeneralNames *sa)
{
    const Extension *e;
    size_t size;

    memset(sa, 0, sizeof(*sa));

    e = find_extension(cert, oid_id_x509_ce_subjectAltName(), i);
    if (e == NULL)
	return HX509_EXTENSION_NOT_FOUND;
    
    return decode_GeneralNames(e->extnValue.data, 
			       e->extnValue.length,
			       sa, &size);
}

static int
add_to_list(hx509_octet_string_list *list, heim_octet_string *entry)
{
    void *p;
    int ret;

    p = realloc(list->val, (list->len + 1) * sizeof(list->val[0]));
    if (p == NULL)
	return ENOMEM;
    list->val = p;
    ret = copy_octet_string(&list->val[list->len], entry);
    if (ret)
	return ret;
    list->len++;
    return 0;
}

void
hx509_free_octet_string_list(hx509_octet_string_list *list)
{
    int i;
    for (i = 0; i < list->len; i++)
	free_octet_string(&list->val[i]);
    free(list->val);
    list->val = NULL;
    list->len = 0;
}

int
hx509_cert_find_subjectAltName_otherName(hx509_cert cert,
					 const heim_oid *oid,
					 hx509_octet_string_list *list)
{
    GeneralNames sa;
    int ret, i, j;

    list->val = NULL;
    list->len = 0;

    i = 0;
    while (1) {
	ret = find_extension_subject_alt_name(_hx509_get_cert(cert), &i, &sa);
	i++;
	if (ret == HX509_EXTENSION_NOT_FOUND)
	    break;


	for (j = 0; j < sa.len; j++) {
	    if (sa.val[j].element == choice_GeneralName_otherName &&
		heim_oid_cmp(&sa.val[j].u.otherName.type_id, oid) == 0) 
	    {
		ret = add_to_list(list, &sa.val[j].u.otherName.value);
		if (ret)
		    return ret;
	    }
	}
	free_GeneralNames(&sa);
    }
    if (ret == HX509_EXTENSION_NOT_FOUND)
	ret = 0;
    return ret;
}


static int
check_key_usage(const Certificate *cert, unsigned flags, int req_present)
{
    const Extension *e;
    KeyUsage ku;
    size_t size;
    int ret, i = 0;
    unsigned ku_flags;

    if (_hx509_cert_get_version(cert) < 3)
	return 0;

    e = find_extension(cert, oid_id_x509_ce_keyUsage(), &i);
    if (e == NULL) {
	if (req_present)
	    return HX509_KU_CERT_MISSING;
	return 0;
    }
    
    ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length, &ku, &size);
    if (ret)
	return ret;
    ku_flags = KeyUsage2int(ku);
    if ((ku_flags & flags) != flags)
	return HX509_KU_CERT_MISSING;
    return 0;
}

int
_hx509_check_key_usage(hx509_cert cert, unsigned flags, int req_present)
{
    return check_key_usage(_hx509_get_cert(cert), flags, req_present);
}


static int
check_basic_constraints(const Certificate *cert, int ca, int depth)
{
    BasicConstraints bc;
    const Extension *e;
    size_t size;
    int ret, i = 0;

    if (_hx509_cert_get_version(cert) < 3)
	return 0;

    e = find_extension(cert, oid_id_x509_ce_basicConstraints(), &i);
    if (e == NULL)
	return HX509_EXTENSION_NOT_FOUND;
    
    ret = decode_BasicConstraints(e->extnValue.data, 
				  e->extnValue.length, &bc,
				  &size);
    if (ret)
	return ret;
    if (ca && (bc.cA == NULL || !*bc.cA))
	ret = HX509_PARENT_NOT_CA;
    if (bc.pathLenConstraint)
	if (depth - 1 > *bc.pathLenConstraint)
	    ret = HX509_CA_PATH_TOO_DEEP;
    free_BasicConstraints(&bc);
    return ret;
}

int
_hx509_cert_is_parent_cmp(const Certificate *subject,
			  const Certificate *issuer,
			  int allow_self_signed)
{
    int diff;
    AuthorityKeyIdentifier ai;
    SubjectKeyIdentifier si;
    int ret_ai, ret_si;

    diff = _hx509_name_cmp(&issuer->tbsCertificate.subject, 
			   &subject->tbsCertificate.issuer);
    if (diff)
	return diff;
    
    memset(&ai, 0, sizeof(ai));
    memset(&si, 0, sizeof(si));

    /*
     * Try to find AuthorityKeyIdentifier, if its not present in the
     * subject certificate nor the parent.
     */

    ret_ai = find_extension_auth_key_id(subject, &ai);
    if (ret_ai && ret_ai != HX509_EXTENSION_NOT_FOUND)
	return 1;
    ret_si = find_extension_subject_key_id(issuer, &si);
    if (ret_si && ret_si != HX509_EXTENSION_NOT_FOUND)
	return -1;

    if (ret_si && ret_ai)
	goto out;
    if (ret_ai)
	goto out;
    if (ret_si) {
	if (allow_self_signed)
	    diff = 0;
	else
	    diff = -1;
	goto out;
    }
    
    if (ai.keyIdentifier == NULL) /* XXX */
	diff = -1; 
    else
	diff = heim_octet_string_cmp(ai.keyIdentifier, &si);
    if (diff)
	goto out;

 out:
    free_AuthorityKeyIdentifier(&ai);
    free_SubjectKeyIdentifier(&si);
    return diff;
}

static int
certificate_is_anchor(hx509_context context,
		      hx509_verify_ctx ctx,
		      const hx509_cert cert)
{
    hx509_query q;
    hx509_cert c;
    int ret;

    _hx509_query_clear(&q);

    q.match = HX509_QUERY_MATCH_CERTIFICATE;
    q.certificate = _hx509_get_cert(cert);

    ret = _hx509_certs_find(context, ctx->trust_anchors, &q, &c);
    if (ret == 0)
	hx509_cert_free(c);
    return ret == 0;
}

static int
certificate_is_self_signed(const Certificate *cert)
{
    return _hx509_cert_is_parent_cmp(cert, cert, 1) == 0;
}

static hx509_cert
find_parent(hx509_context context,
	    hx509_verify_ctx ctx,
	    hx509_path *path,
	    hx509_certs chain, 
	    hx509_cert current)
{
    hx509_query q;
    hx509_cert c;
    int ret;

    _hx509_query_clear(&q);

    q.match = 
	HX509_QUERY_FIND_ISSUER_CERT | 
	HX509_QUERY_NO_MATCH_PATH |
	HX509_QUERY_KU_KEYCERTSIGN;
    q.subject = _hx509_get_cert(current);
    q.path = path;

    ret = _hx509_certs_find(context, chain, &q, &c);
    if (ret == 0)
	return c;
    ret = _hx509_certs_find(context, ctx->trust_anchors, &q, &c);
    if (ret == 0)
	return c;
    return NULL;
}

/*
 * Path operations are like MEMORY based keyset, but with exposed
 * internal so we can do easy searches.
 */

static int
path_append(hx509_path *path, hx509_cert cert)
{
    hx509_cert *val;
    val = realloc(path->val, (path->len + 1) * sizeof(path->val[0]));
    if (val == NULL)
	return ENOMEM;

    path->val = val;
    path->val[path->len] = hx509_cert_ref(cert);
    path->len++;

    return 0;
}

static void
path_free(hx509_path *path)
{
    unsigned i;
    
    for (i = 0; i < path->len; i++)
	hx509_cert_free(path->val[i]);
    free(path->val);
}

/*
 * Find path by looking up issuer for the top certificate and continue
 * until an anchor certificate is found. A certificate never included
 * twice in the path.
 *
 * The path includes a path from the top certificate to the anchor
 * certificate.
 */

static int
calculate_path(hx509_context context,
	       hx509_verify_ctx ctx,
	       hx509_cert cert,
	       hx509_certs chain,
	       hx509_path *path)
{
    hx509_cert parent, current;
    int ret;

    ret = path_append(path, cert);
    if (ret)
	return ret;

    current = hx509_cert_ref(cert);

    while (!certificate_is_anchor(context, ctx, current)) {

	parent = find_parent(context, ctx, path, chain, current);
	hx509_cert_free(current);
	if (parent == NULL)
	    return HX509_ISSUER_NOT_FOUND;

	ret = path_append(path, parent);
	if (ret)
	    return ret;
	current = parent;

	if (path->len > ctx->max_depth)
	    return HX509_PATH_TOO_LONG;
    }
    hx509_cert_free(current);
    return 0;
}

static int
AlgorithmIdentifier_cmp(const AlgorithmIdentifier *p,
			const AlgorithmIdentifier *q)
{
    int diff;
    diff = heim_oid_cmp(&p->algorithm, &q->algorithm);
    if (diff)
	return diff;
    if (p->parameters) {
	if (q->parameters)
	    return heim_any_cmp(p->parameters,
				q->parameters);
	else
	    return 1;
    } else {
	if (q->parameters)
	    return -1;
	else
	    return 0;
    }
}

int
_hx509_Certificate_cmp(const Certificate *p, const Certificate *q)
{
    int diff;
    diff = heim_bit_string_cmp(&p->signatureValue, &q->signatureValue);
    if (diff)
	return diff;
    diff = AlgorithmIdentifier_cmp(&p->signatureAlgorithm, 
				   &q->signatureAlgorithm);
    if (diff)
	return diff;
    diff = heim_octet_string_cmp(&p->tbsCertificate._save,
				 &q->tbsCertificate._save);
    return diff;
}

int
hx509_cert_cmp(hx509_cert p, hx509_cert q)
{
    return _hx509_Certificate_cmp(p->data, q->data);
}

int
hx509_cert_get_issuer(hx509_cert p, hx509_name *name)
{
    return _hx509_name_from_Name(&p->data->tbsCertificate.issuer, name);
}

int
hx509_cert_get_subject(hx509_cert p, hx509_name *name)
{
    return _hx509_name_from_Name(&p->data->tbsCertificate.subject, name);
}

int
hx509_cert_get_serialnumber(hx509_cert p, heim_integer *i)
{
    return copy_heim_integer(&p->data->tbsCertificate.serialNumber, i);
}

hx509_private_key
_hx509_cert_private_key(hx509_cert p)
{
    return p->private_key;
}

int
_hx509_cert_private_decrypt(const heim_octet_string *ciphertext,
			    const heim_oid *encryption_oid,
			    hx509_cert p,
			    heim_octet_string *cleartext)
{
    cleartext->data = NULL;
    cleartext->length = 0;

    if (p->private_key == NULL)
	return EINVAL;

    return _hx509_private_key_private_decrypt(ciphertext,
					      encryption_oid,
					      p->private_key, 
					      cleartext);
}

int
_hx509_cert_public_encrypt(const heim_octet_string *cleartext,
			   const hx509_cert p,
			   heim_oid *encryption_oid,
			   heim_octet_string *ciphertext)
{
    return _hx509_public_encrypt(cleartext, p->data,
				 encryption_oid, ciphertext);
}

int
_hx509_cert_private_sigature(const heim_octet_string *cleartext,
			     const heim_oid *signature_oid,
			     hx509_cert p,
			     heim_octet_string *signature)
{
    memset(signature, 0, sizeof(*signature));
    return 0;
}
    

/*
 *
 */

time_t
_hx509_Time2time_t(const Time *t)
{
    switch(t->element) {
    case choice_Time_utcTime:
	return t->u.utcTime;
    case choice_Time_generalTime:
	return t->u.generalTime;
    }
    return 0;
}

/*
 *
 */

static int
init_name_constraints(hx509_name_constraints *nc)
{
    memset(nc, 0, sizeof(*nc));

    nc->nc.permittedSubtrees = calloc(1, sizeof(*nc->nc.permittedSubtrees));
    if (nc->nc.permittedSubtrees == NULL)
	return ENOMEM;
    nc->nc.excludedSubtrees = calloc(1, sizeof(*nc->nc.excludedSubtrees));
    if (nc->nc.excludedSubtrees == NULL) {
	free(nc->nc.permittedSubtrees);
	nc->nc.permittedSubtrees = NULL;
	return ENOMEM;
    }
    return 0;
}

static int
append_tree(const GeneralSubtrees *add, GeneralSubtrees *merge)
{
    unsigned int num, i;
    GeneralSubtree *st;
    int ret;
	    
    num = merge->len + add->len;
    if (num < merge->len)
	return HX509_RANGE;
    if (num > UINT_MAX/sizeof(merge->val[0]))
	return HX509_RANGE;
    st = realloc(merge->val, sizeof(*st) * num);
    if (st == NULL)
	return ENOMEM;
    merge->val = st;
    memset(&st[merge->len], 0, sizeof(add->val[0]) * add->len);
    for (i = 0; i < add->len; i++) {
	ret = copy_GeneralSubtree(&add->val[i],
				  &merge->val[merge->len + i]);
	if (ret)
	    return ret;
    }
    merge->len = num;

    return 0;
}

static int
add_name_constraints(const Certificate *c, int not_ca,
		     hx509_name_constraints *nc)
{
    NameConstraints tnc;
    int ret;

    ret = find_extension_name_constraints(c, &tnc);
    if (ret == HX509_EXTENSION_NOT_FOUND)
	return 0;
    else if (ret)
	return ret;
    else if (not_ca) {
	ret = HX509_VERIFY_CONSTRAINTS;
    } else {
	GeneralSubtrees gs;
	if (tnc.permittedSubtrees) {
	    GeneralSubtrees_SET(&gs, tnc.permittedSubtrees);
	    ret = append_tree(&gs, nc->nc.permittedSubtrees);
	}
	if (ret == 0 && tnc.excludedSubtrees) {
	    GeneralSubtrees_SET(&gs, tnc.excludedSubtrees);
	    ret = append_tree(&gs, nc->nc.excludedSubtrees);
	}
    }
    free_NameConstraints(&tnc);
    return ret;
}

static int
match_RDN(const RelativeDistinguishedName *c,
	  const RelativeDistinguishedName *n)
{
    int i;

    if (c->len != n->len)
	return HX509_NAME_CONSTRAINT_ERROR;
    
    for (i = 0; i < n->len; i++) {
	if (heim_oid_cmp(&c->val[i].type, &n->val[i].type) != 0)
	    return HX509_NAME_CONSTRAINT_ERROR;
	if (_hx509_name_ds_cmp(&c->val[i].value, &n->val[i].value) != 0)
	    return HX509_NAME_CONSTRAINT_ERROR;
    }
    return 0;
}

static int
match_X501Name(const Name *c, const Name *n)
{
    int i, j, ret;

    if (c->element != choice_Name_rdnSequence
	|| n->element != choice_Name_rdnSequence)
	return 0;
    if (c->u.rdnSequence.len > n->u.rdnSequence.len)
	return HX509_NAME_CONSTRAINT_ERROR;
    for (i = c->u.rdnSequence.len - 1, j = n->u.rdnSequence.len - 1;
	 i >= 0; i--, j--) {
	ret = match_RDN(&c->u.rdnSequence.val[i], &c->u.rdnSequence.val[j]);
	if (ret)
	    return ret;
    }
    return 0;
} 


static int
match_general_name(const GeneralName *c, const GeneralName *n)
{
    if (c->element != n->element)
	return 0;

    switch(c->element) {
    case choice_GeneralName_otherName:
	if (heim_oid_cmp(&c->u.otherName.type_id,
			 &n->u.otherName.type_id) != 0)
	    return HX509_NAME_CONSTRAINT_ERROR;
	if (heim_any_cmp(&c->u.otherName.value,
			 &n->u.otherName.value) != 0)
	    return HX509_NAME_CONSTRAINT_ERROR;
	return 0;
    case choice_GeneralName_rfc822Name: {
	const char *s;
	size_t len1, len2;
	s = strchr(c->u.rfc822Name, '@');
	if (s) {
	    if (strcasecmp(c->u.rfc822Name, n->u.rfc822Name) != 0)
		return HX509_NAME_CONSTRAINT_ERROR;
	} else {
	    s = strchr(n->u.rfc822Name, '@');
	    if (s == NULL)
		return HX509_NAME_CONSTRAINT_ERROR;
	    len1 = strlen(c->u.rfc822Name);
	    len2 = strlen(s + 1);
	    if (len1 > len2)
		return HX509_NAME_CONSTRAINT_ERROR;
	    if (strcasecmp(s + 1 + len2 - len1, c->u.rfc822Name) != 0)
		return HX509_NAME_CONSTRAINT_ERROR;
	    if (len1 < len2 && s[len2 - len1] != '.')
		return HX509_NAME_CONSTRAINT_ERROR;
	}
	return 0;
    }
    case choice_GeneralName_dNSName: {
	size_t len1, len2;

	len1 = strlen(c->u.dNSName);
	len2 = strlen(n->u.dNSName);
	if (len1 > len2)
	    return HX509_NAME_CONSTRAINT_ERROR;
	if (strcasecmp(&n->u.dNSName[len2 - len1], c->u.dNSName) != 0)
	    return HX509_NAME_CONSTRAINT_ERROR;
	return 0;
    }
    case choice_GeneralName_directoryName: {
	Name c_name, n_name;
	c_name._save.data = NULL;
	c_name._save.length = 0;
	c_name.element = c->u.directoryName.element;
	c_name.u.rdnSequence = c->u.directoryName.u.rdnSequence;

	n_name._save.data = NULL;
	n_name._save.length = 0;
	n_name.element = n->u.directoryName.element;
	n_name.u.rdnSequence = n->u.directoryName.u.rdnSequence;

	return match_X501Name(&c_name, &n_name);
    }
    case choice_GeneralName_uniformResourceIdentifier:
    case choice_GeneralName_iPAddress:
    case choice_GeneralName_registeredID:
    default:
	return HX509_NAME_CONSTRAINT_ERROR;
    }
}


static int
match_name(const GeneralName *n, const Certificate *c)
{
    GeneralName certname;
    GeneralNames sa;
    int ret, i, j;

    certname.element = choice_GeneralName_directoryName;
    /* certname.u.directoryName = c->tbsCertificate.subject; */

    certname.u.directoryName.element = c->tbsCertificate.subject.element;
    certname.u.directoryName.u.rdnSequence = 
	c->tbsCertificate.subject.u.rdnSequence;
    
    ret = match_general_name(n, &certname);
    if (ret)
	return ret;

    i = 0;
    do {
	ret = find_extension_subject_alt_name(c, &i, &sa);
	if (ret == HX509_EXTENSION_NOT_FOUND) {
	    ret = 0;
	    break;
	} else if (ret != 0)
	    break;

	for (j = 0; j < sa.len; j++) {
	    ret = match_general_name(n, &sa.val[j]);
	    if (ret)
		break;
	}
	free_GeneralNames(&sa);
    } while (ret == 0);

    return ret;
}

static int
match_tree(const GeneralSubtrees *t, const Certificate *c, int *match)
{
    unsigned int i;
    *match = 0;
    for (i = 0; i < t->len; i++) {
	if (t->val[i].minimum && t->val[i].maximum)
	    return HX509_RANGE;
	if (match_name(&t->val[i].base, c))
	    *match = 1;
    }
    return 0;
}

static int
check_name_constraints(const hx509_name_constraints *nc,
		       const Certificate *c)
{
    GeneralSubtrees gs;
    int match, ret;

    if (nc->nc.permittedSubtrees->len > 0) {
	GeneralSubtrees_SET(&gs, nc->nc.permittedSubtrees);

	ret = match_tree(&gs, c, &match);
	if (ret)
	    return ret;
	if (match == 0)
	    return HX509_VERIFY_CONSTRAINTS;
    }
    if (nc->nc.excludedSubtrees->len > 0) {
	GeneralSubtrees_SET(&gs, nc->nc.excludedSubtrees);

	ret = match_tree(&gs, c, &match);
	if (ret)
	    return ret;
	if (match)
	    return HX509_VERIFY_CONSTRAINTS;
    }
    return 0;
}

static void
free_name_constraints(hx509_name_constraints *nc)
{
    /* free_NameConstraints(&nc->nc); */
    if (nc->nc.permittedSubtrees) {
	free_GeneralSubtrees(nc->nc.permittedSubtrees);
	free(nc->nc.permittedSubtrees);
	nc->nc.permittedSubtrees = NULL;
    }
    if (nc->nc.excludedSubtrees) {
	free_GeneralSubtrees(nc->nc.excludedSubtrees);
	free(nc->nc.excludedSubtrees);
	nc->nc.excludedSubtrees = NULL;
    }
}

int
hx509_verify_path(hx509_context context,
		  hx509_verify_ctx ctx,
		  hx509_cert cert,
		  hx509_certs chain)
{
    hx509_name_constraints nc;
    hx509_path path;
#if 0
    const AlgorithmIdentifier *alg_id;
#endif
    int ret, i;

    ret = init_name_constraints(&nc);
    if (ret)	
	return ret;

    path.val = NULL;
    path.len = 0;

    if ((ctx->flags & HX509_VERIFY_CTX_F_TIME_SET) == 0)
	ctx->time_now = time(NULL);

    /*
     * Calculate the path from the certificate user presented to the
     * to an anchor.
     */
    ret = calculate_path(context, ctx, cert, chain, &path);
    if (ret)
	goto out;

#if 0
    alg_id = path.val[path->len - 1]->data->tbsCertificate.signature;
#endif

    /*
     * Verify constraints, do this backward so path constraints are
     * checked in the right order.
     */

    for (ret = 0, i = path.len - 1; i >= 0; i--) {
	Certificate *c;

	c = _hx509_get_cert(path.val[i]);

#if 0
	/* check that algorithm and parameters is the same */
	/* XXX this is wrong */
	ret = alg_cmp(&c->tbsCertificate.signature, alg_id);
	if (ret) {
	    ret = HX509_PATH_ALGORITHM_CHANGED;
	    goto out;
	}
#endif

	/*
	 * Lets do some basic check on issuer like
	 * keyUsage.keyCertSign and basicConstraints.cA bit.
	 */
	if (i != 0) {
	    if (check_key_usage(c, 1 << 5, TRUE)) { /* XXX make constants */
		ret = ENOENT;
		goto out;
	    }
	    if (check_basic_constraints(c, 1, path.len - i - 1)) {
		ret = ENOENT;
		goto out;
	    }
	}

	{
	    time_t t;

	    t = _hx509_Time2time_t(&c->tbsCertificate.validity.notBefore);
	    if (t > ctx->time_now) {
		ret = HX509_CERT_USED_BEFORE_TIME;
		goto out;
	    }
	    t = _hx509_Time2time_t(&c->tbsCertificate.validity.notAfter);
	    if (t < ctx->time_now) {
		ret = HX509_CERT_USED_AFTER_TIME;
		goto out;
	    }
	}

	/* verify name constraints, not for selfsigned and anchor */
	if (!certificate_is_self_signed(c) || i == path.len - 1) {
	    ret = check_name_constraints(&nc, c);
	    if (ret)
		goto out;
	}
	ret = add_name_constraints(c, i == 0, &nc);
	if (ret)
	    goto out;

	/* XXX verify all other silly constraints */

    }

    /*
     * Verify no certificates has been revoked.
     */

    if (ctx->revoke_ctx) {
	for (i = path.len - 1; i >= 0; i--) {
	    ret = hx509_revoke_verify(context,  ctx->revoke_ctx, ctx->time_now,
				      path.val[i]);
	    if (ret)
		goto out;
	}
    }

    /*
     * Verify signatures, do this backward so public key working
     * parameter is passed up from the anchor up though the chain.
     */

    for (i = path.len - 1; i >= 0; i--) {
	Certificate *signer, *c;
	heim_octet_string os;

	c = _hx509_get_cert(path.val[i]);
	/* is last in chain and thus the self-signed */
	signer = path.val[i == path.len - 1 ? i : i + 1]->data;

	if (c->signatureValue.length & 7) {
	    ret = EINVAL;
	    break;
	}
	os.data = c->signatureValue.data;
	os.length = c->signatureValue.length / 8;

	/* verify signatureValue */
	ret = _hx509_verify_signature(signer, 
				      &c->signatureAlgorithm,
				      &c->tbsCertificate._save,
				      &os);
	if (ret) {
	    break;
	}
    }

 out:
    free_name_constraints(&nc);
    path_free(&path);

    return ret;
}

int
hx509_verify_signature(hx509_context context,
		       const hx509_cert signer,
		       const AlgorithmIdentifier *alg,
		       const heim_octet_string *data,
		       const heim_octet_string *sig)
{
    return _hx509_verify_signature(signer->data, alg, data, sig);
}

int
_hx509_set_cert_attribute(hx509_cert cert, const heim_oid *oid, 
			  const heim_octet_string *attr)
{
    hx509_cert_attribute a;
    void *d;

    if (hx509_cert_get_attribute(cert, oid) != NULL)
	return 0;

    d = realloc(cert->attrs.val, 
		sizeof(cert->attrs.val[0]) * (cert->attrs.len + 1));
    if (d == NULL)
	return ENOMEM;
    cert->attrs.val = d;

    a = malloc(sizeof(*a));
    if (a == NULL)
	return ENOMEM;

    copy_octet_string(attr, &a->data);
    copy_oid(oid, &a->oid);
    
    cert->attrs.val[cert->attrs.len] = a;
    cert->attrs.len++;

    return 0;
}

hx509_cert_attribute
hx509_cert_get_attribute(hx509_cert cert, const heim_oid *oid)
{
    int i;
    for (i = 0; i < cert->attrs.len; i++)
	if (heim_oid_cmp(oid, &cert->attrs.val[i]->oid) == 0)
	    return cert->attrs.val[i];
    return NULL;
}

int
hx509_cert_set_friendly_name(hx509_cert cert, const char *name)
{
    if (cert->friendlyname)
	free(cert->friendlyname);
    cert->friendlyname = strdup(name);
    if (cert->friendlyname == NULL)
	return ENOMEM;
    return 0;
}


const char *
hx509_cert_get_friendly_name(hx509_cert cert)
{
    hx509_cert_attribute a;
    PKCS9_friendlyName n;
    size_t sz;
    int ret, i;

    if (cert->friendlyname)
	return cert->friendlyname;

    a = hx509_cert_get_attribute(cert, oid_id_pkcs_9_at_friendlyName());
    if (a == NULL) {
	/* XXX use subject name ? */
	return NULL; 
    }

    ret = decode_PKCS9_friendlyName(a->data.data, a->data.length, &n, &sz);
    if (ret)
	return NULL;
	
    if (n.len != 1) {
	free_PKCS9_friendlyName(&n);
	return NULL;
    }
    
    cert->friendlyname = malloc(n.val[0].length + 1);
    if (cert->friendlyname == NULL) {
	free_PKCS9_friendlyName(&n);
	return NULL;
    }
    
    for (i = 0; i < n.val[0].length; i++) {
	if (n.val[0].data[i] <= 0xff)
	    cert->friendlyname[i] = n.val[0].data[i] & 0xff;
	else
	    cert->friendlyname[i] = 'X';
    }
    cert->friendlyname[i] = '\0';
    free_PKCS9_friendlyName(&n);

    return cert->friendlyname;
}

void
_hx509_query_clear(hx509_query *q)
{
    memset(q, 0, sizeof(*q));
}

int
_hx509_query_match_cert(const hx509_query *q, hx509_cert cert)
{
    Certificate *c = _hx509_get_cert(cert);

    if ((q->match & HX509_QUERY_FIND_ISSUER_CERT) &&
	_hx509_cert_is_parent_cmp(q->subject, c, 0) != 0)
	return 0;

    if ((q->match & HX509_QUERY_MATCH_CERTIFICATE) &&
	_hx509_Certificate_cmp(q->certificate, c) != 0)
	return 0;

    if ((q->match & HX509_QUERY_MATCH_SERIALNUMBER)
	&& heim_integer_cmp(&c->tbsCertificate.serialNumber, q->serial) != 0)
	return 0;

    if ((q->match & HX509_QUERY_MATCH_ISSUER_NAME)
	&& _hx509_name_cmp(&c->tbsCertificate.issuer, q->issuer_name) != 0)
	return 0;

    if ((q->match & HX509_QUERY_MATCH_SUBJECT_NAME)
	&& _hx509_name_cmp(&c->tbsCertificate.subject, q->subject_name) != 0)
	return 0;

    if (q->match & HX509_QUERY_MATCH_SUBJECT_KEY_ID) {
	SubjectKeyIdentifier si;
	int ret;

	ret = find_extension_subject_key_id(c, &si);
	if (ret == 0) {
	    if (heim_octet_string_cmp(&si, q->subject_id) != 0)
		ret = 1;
	    free_SubjectKeyIdentifier(&si);
	}
	if (ret)
	    return 0;
    }
    if ((q->match & HX509_QUERY_MATCH_ISSUER_ID))
	return 0;
    if ((q->match & HX509_QUERY_PRIVATE_KEY) && 
	_hx509_cert_private_key(cert) == NULL)
	return 0;

    {
	unsigned ku = 0;
	if (q->match & HX509_QUERY_KU_DIGITALSIGNATURE)
	    ku |= (1 << 0);
	if (q->match & HX509_QUERY_KU_NONREPUDIATION)
	    ku |= (1 << 1);
	if (q->match & HX509_QUERY_KU_ENCIPHERMENT)
	    ku |= (1 << 2);
	if (q->match & HX509_QUERY_KU_DATAENCIPHERMENT)
	    ku |= (1 << 3);
	if (q->match & HX509_QUERY_KU_KEYAGREEMENT)
	    ku |= (1 << 4);
	if (q->match & HX509_QUERY_KU_KEYCERTSIGN)
	    ku |= (1 << 5);
	if (q->match & HX509_QUERY_KU_CRLSIGN)
	    ku |= (1 << 6);
	if (ku && check_key_usage(c, ku, TRUE))
	    return 0;
    }
    if ((q->match & HX509_QUERY_ANCHOR))
	return 0;

    if (q->match & HX509_QUERY_MATCH_LOCAL_KEY_ID) {
	hx509_cert_attribute a;

	a = hx509_cert_get_attribute(cert, oid_id_pkcs_9_at_localKeyId());
	if (a == NULL)
	    return 0;
	if (heim_octet_string_cmp(&a->data, q->local_key_id) != 0)
	    return 0;
    }

    if (q->match & HX509_QUERY_NO_MATCH_PATH) {
	size_t i;

	for (i = 0; i < q->path->len; i++)
	    if (hx509_cert_cmp(q->path->val[i], cert) == 0)
		return 0;
    }
    if (q->match & HX509_QUERY_MATCH_FRIENDLY_NAME) {
	const char *name = hx509_cert_get_friendly_name(cert);
	if (name == NULL)
	    return 0;
	if (strcasecmp(q->friendlyname, name) != 0)
	    return 0;
    }
    if (q->match & HX509_QUERY_MATCH_FUNCTION) {
	int ret = (*q->cmp_func)(cert);
	if (ret != 0)
	    return 0;
    }

    if (q->match & ~HX509_QUERY_MASK)
	return 0;

    return 1;
}
