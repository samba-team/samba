/*
 * Copyright (c) 2006 - 2008 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "krb5/gsskrb5_locl.h"
#include <err.h>
#include <getarg.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <gssapi_spnego.h>
#include <gssapi_ntlm.h>
#include "test_common.h"

#ifdef NOTYET
/*
 * export/import of sec contexts on the initiator side
 * don't work properly, yet.
 */
#define DO_IMPORT_EXPORT_OF_CLIENT_CONTEXT 1
#endif

static char *type_string;
static char *mech_string;
static char *mechs_string;
static char *ret_mech_string;
static char *localname_string;
static char *client_name;
static char *client_password;
static char *localname_string;
static char *on_behalf_of_string;
static int dns_canon_flag = -1;
static int mutual_auth_flag = 0;
static int dce_style_flag = 0;
static int wrapunwrap_flag = 0;
static int iov_flag = 0;
static int aead_flag = 0;
static int getverifymic_flag = 0;
static int deleg_flag = 0;
static int anon_flag = 0;
static int policy_deleg_flag = 0;
static int server_no_deleg_flag = 0;
static int ei_cred_flag = 0;
static int ei_ctx_flag = 0;
static char *client_ccache = NULL;
static char *client_keytab = NULL;
static char *gsskrb5_acceptor_identity = NULL;
static char *session_enctype_string = NULL;
static int client_time_offset = 0;
static int server_time_offset = 0;
static int max_loops = 0;
static char *limit_enctype_string = NULL;
static int token_split  = 0;
static int version_flag = 0;
static int verbose_flag = 0;
static int help_flag	= 0;
static char *i_channel_bindings = NULL;
static char *a_channel_bindings = NULL;

static krb5_context context;
static krb5_enctype limit_enctype = 0;

static gss_OID
string_to_oid(const char *name)
{
    gss_OID oid = gss_name_to_oid(name);

    if (oid == GSS_C_NO_OID)
	errx(1, "name '%s' not known", name);

    return oid;
}

static void
string_to_oids(gss_OID_set *oidsetp, char *names)
{
    OM_uint32 maj_stat, min_stat;
    char *name;
    char *s;

    if (names[0] == '\0') {
        *oidsetp = GSS_C_NO_OID_SET;
        return;
    }

    if (strcasecmp(names, "all") == 0) {
	maj_stat = gss_indicate_mechs(&min_stat, oidsetp);
	if (GSS_ERROR(maj_stat))
	    errx(1, "gss_indicate_mechs: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    } else {
	maj_stat = gss_create_empty_oid_set(&min_stat, oidsetp);
	if (GSS_ERROR(maj_stat))
	    errx(1, "gss_create_empty_oid_set: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));

        for (name = strtok_r(names, ", ", &s);
             name != NULL;
             name = strtok_r(NULL, ", ", &s)) {
	    gss_OID oid = string_to_oid(name);

	    maj_stat = gss_add_oid_set_member(&min_stat, oid, oidsetp);
	    if (GSS_ERROR(maj_stat))
		errx(1, "gss_add_oid_set_member: %s",
		    gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
        }
    }
}

static void
show_pac_client_info(gss_name_t n)
{
    gss_buffer_desc dv = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc v = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc a;
    OM_uint32 maj, min;
    int authenticated, complete, more, name_is_MN, found;
    gss_OID MN_mech;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    size_t i;

    krb5_error_code ret;
    krb5_storage *sp = NULL;
    uint16_t len = 0, *s;
    uint64_t tmp;
    char *logon_string = NULL;

    maj = gss_inquire_name(&min, n, &name_is_MN, &MN_mech, &attrs);
    if (maj != GSS_S_COMPLETE)
	errx(1, "gss_inquire_name: %s",
	     gssapi_err(maj, min, GSS_KRB5_MECHANISM));

    a.value = "urn:mspac:client-info";
    a.length = sizeof("urn:mspac:client-info") - 1;

    for (found = 0, i = 0; i < attrs->count; i++) {
	gss_buffer_t attr = &attrs->elements[i];

	if (attr->length == a.length &&
	    memcmp(attr->value, a.value, a.length) == 0) {
	    found++;
	    break;
	}
    }

    gss_release_buffer_set(&min, &attrs);

    if (!found)
	errx(1, "gss_inquire_name: attribute %.*s not enumerated",
	     (int)a.length, (char *)a.value);

    more = 0;
    maj = gss_get_name_attribute(&min, n, &a, &authenticated, &complete, &v,
                                 &dv, &more);
    if (maj != GSS_S_COMPLETE)
	errx(1, "gss_get_name_attribute: %s",
	     gssapi_err(maj, min, GSS_KRB5_MECHANISM));


    sp = krb5_storage_from_readonly_mem(v.value, v.length);
    if (sp == NULL)
	errx(1, "show_pac_client_info: out of memory");

    krb5_storage_set_flags(sp, KRB5_STORAGE_BYTEORDER_LE);

    ret = krb5_ret_uint64(sp, &tmp); /* skip over time */
    if (ret == 0)
	ret = krb5_ret_uint16(sp, &len);
    if (ret || len == 0)
	errx(1, "show_pac_client_info: invalid PAC logon info length");

    s = malloc(len);
    ret = krb5_storage_read(sp, s, len);
    if (ret != len)
	errx(1, "show_pac_client_info:, failed to read PAC logon name");

    krb5_storage_free(sp);

    {
	size_t ucs2len = len / 2;
	uint16_t *ucs2;
	size_t u8len;
	unsigned int flags = WIND_RW_LE;

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2len);
	if (ucs2 == NULL)
	    errx(1, "show_pac_client_info: out of memory");

	ret = wind_ucs2read(s, len, &flags, ucs2, &ucs2len);
	free(s);
	if (ret)
	    errx(1, "failed to convert string to UCS-2");

	ret = wind_ucs2utf8_length(ucs2, ucs2len, &u8len);
	if (ret)
	    errx(1, "failed to count length of UCS-2 string");

	u8len += 1; /* Add space for NUL */
	logon_string = malloc(u8len);
	if (logon_string == NULL)
	    errx(1, "show_pac_client_info: out of memory");

	ret = wind_ucs2utf8(ucs2, ucs2len, logon_string, &u8len);
	free(ucs2);
	if (ret)
	    errx(1, "failed to convert to UTF-8");
    }

    printf("logon name: %s\n", logon_string);
    free(logon_string);

    gss_release_buffer(&min, &dv);
    gss_release_buffer(&min, &v);
}

static void
loop(gss_OID mechoid,
     gss_OID nameoid, const char *target,
     gss_cred_id_t init_cred,
     gss_ctx_id_t *sctx, gss_ctx_id_t *cctx,
     gss_OID *actual_mech,
     gss_cred_id_t *deleg_cred)
{
    int server_done = 0, client_done = 0;
    int num_loops = 0;
    OM_uint32 maj_stat, min_stat;
    gss_name_t gss_target_name, src_name = GSS_C_NO_NAME;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
#ifdef DO_IMPORT_EXPORT_OF_CLIENT_CONTEXT
    gss_buffer_desc cctx_tok = GSS_C_EMPTY_BUFFER;
#endif
    gss_buffer_desc sctx_tok = GSS_C_EMPTY_BUFFER;
    OM_uint32 flags = 0, ret_cflags = 0, ret_sflags = 0;
    gss_OID actual_mech_client = GSS_C_NO_OID;
    gss_OID actual_mech_server = GSS_C_NO_OID;
    struct gss_channel_bindings_struct i_channel_bindings_data;
    struct gss_channel_bindings_struct a_channel_bindings_data;
    gss_channel_bindings_t i_channel_bindings_p = GSS_C_NO_CHANNEL_BINDINGS;
    gss_channel_bindings_t a_channel_bindings_p = GSS_C_NO_CHANNEL_BINDINGS;
    size_t offset = 0;

    memset(&i_channel_bindings_data, 0, sizeof(i_channel_bindings_data));
    memset(&a_channel_bindings_data, 0, sizeof(a_channel_bindings_data));

    *actual_mech = GSS_C_NO_OID;

    flags |= GSS_C_REPLAY_FLAG;
    flags |= GSS_C_INTEG_FLAG;
    flags |= GSS_C_CONF_FLAG;

    if (mutual_auth_flag)
	flags |= GSS_C_MUTUAL_FLAG;
    if (anon_flag)
	flags |= GSS_C_ANON_FLAG;
    if (dce_style_flag)
	flags |= GSS_C_DCE_STYLE;
    if (deleg_flag)
	flags |= GSS_C_DELEG_FLAG;
    if (policy_deleg_flag)
	flags |= GSS_C_DELEG_POLICY_FLAG;

    input_token.value = rk_UNCONST(target);
    input_token.length = strlen(target);

    maj_stat = gss_import_name(&min_stat,
			       &input_token,
			       nameoid,
			       &gss_target_name);
    if (GSS_ERROR(maj_stat))
	err(1, "import name creds failed with: %d", maj_stat);

    if (on_behalf_of_string) {
        AuthorizationDataElement e;
        gss_buffer_desc attr, value;
        int32_t kret;
        size_t sz;

        memset(&e, 0, sizeof(e));
        e.ad_type = KRB5_AUTHDATA_ON_BEHALF_OF;
        e.ad_data.length = strlen(on_behalf_of_string);
        e.ad_data.data = on_behalf_of_string;
        ASN1_MALLOC_ENCODE(AuthorizationDataElement, value.value, value.length,
                           &e, &sz, kret);
        if (kret)
            errx(1, "Could not encode AD-ON-BEHALF-OF AuthorizationDataElement");
        attr.value =
            GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "authenticator-authz-data";
        attr.length =
            sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "authenticator-authz-data") - 1;
        maj_stat = gss_set_name_attribute(&min_stat, gss_target_name, 1, &attr,
                                          &value);
        if (maj_stat != GSS_S_COMPLETE)
            errx(1, "gss_set_name_attribute() failed with: %s",
                 gssapi_err(maj_stat, min_stat, GSS_KRB5_MECHANISM));
        free(value.value);
    }

    input_token.length = 0;
    input_token.value = NULL;

    if (i_channel_bindings) {
	i_channel_bindings_data.application_data.length = strlen(i_channel_bindings);
	i_channel_bindings_data.application_data.value = i_channel_bindings;
	i_channel_bindings_p = &i_channel_bindings_data;
    }
    if (a_channel_bindings) {
	a_channel_bindings_data.application_data.length = strlen(a_channel_bindings);
	a_channel_bindings_data.application_data.value = a_channel_bindings;
	a_channel_bindings_p = &a_channel_bindings_data;
    }

    /*
     * This loop simulates both the initiator and acceptor sides of
     * a GSS conversation.  We also simulate tokens that are broken
     * into pieces before handed to gss_accept_sec_context().  Each
     * iteration of the loop optionally calls gss_init_sec_context()
     * then optionally calls gss_accept_sec_context().
     */

    while (!server_done || !client_done) {
	num_loops++;
        if (verbose_flag)
            printf("loop #%d: input_token.length=%zu client_done=%d\n",
                num_loops, input_token.length, client_done);

        /*
         * First, we need to call gss_import_sec_context() if we are
         * running through the loop the first time, or if we have been
         * given a token (input_token) by gss_accept_sec_context().
         * We aren't going to be called every time because when we are
         * using split tokens, we may need to call gss_accept_sec_context()
         * multiple times because it receives an entire token.
         */
        if ((num_loops == 1 || input_token.length > 0) && !client_done) {
            gsskrb5_set_time_offset(client_time_offset);
#ifdef DO_IMPORT_EXPORT_OF_CLIENT_CONTEXT
            if (ei_ctx_flag && cctx_tok.length > 0) {
                maj_stat = gss_import_sec_context(&min_stat, &cctx_tok, cctx);
                if (maj_stat != GSS_S_COMPLETE)
                    errx(1, "import client context failed: %s",
                         gssapi_err(maj_stat, min_stat, NULL));
                gss_release_buffer(&min_stat, &cctx_tok);
            }
#endif

            maj_stat = gss_init_sec_context(&min_stat, init_cred, cctx,
                                            gss_target_name, mechoid,
                                            flags, 0, i_channel_bindings_p,
                                            &input_token, &actual_mech_client,
                                            &output_token, &ret_cflags, NULL);
            if (GSS_ERROR(maj_stat))
                errx(1, "init_sec_context: %s",
                     gssapi_err(maj_stat, min_stat, mechoid));
            client_done = !(maj_stat & GSS_S_CONTINUE_NEEDED);

	    gss_release_buffer(&min_stat, &input_token);
            input_token.length = 0;
            input_token.value  = NULL;

#if DO_IMPORT_EXPORT_OF_CLIENT_CONTEXT
            if (!client_done && ei_ctx_flag) {
                maj_stat = gss_export_sec_context(&min_stat, cctx, &cctx_tok);
                if (maj_stat != GSS_S_COMPLETE)
                    errx(1, "export server context failed: %s",
                         gssapi_err(maj_stat, min_stat, NULL));
                if (*cctx != GSS_C_NO_CONTEXT)
                    errx(1, "export client context did not release it");
            }
#endif

            if (verbose_flag)
                printf("loop #%d: output_token.length=%zu\n", num_loops,
                    output_token.length);

            offset = 0;
        }

        /*
         * We now call gss_accept_sec_context().  To support split
         * tokens, we keep track of the offset into the token that
         * we have used and keep handing in chunks until we're done.
         */

        if (offset < output_token.length && !server_done) {
            gss_buffer_desc tmp;

            gsskrb5_get_time_offset(&client_time_offset);
            gsskrb5_set_time_offset(server_time_offset);

	    if (output_token.length && ((uint8_t *)output_token.value)[0] == 0x60) {
		tmp.length = output_token.length - offset;
		if (token_split && tmp.length > token_split)
		    tmp.length = token_split;
		tmp.value  = (char *)output_token.value + offset;
	    } else
		tmp = output_token;

            if (verbose_flag)
                printf("loop #%d: accept offset=%zu len=%zu\n", num_loops,
                    offset, tmp.length);

            if (ei_ctx_flag && sctx_tok.length > 0) {
                maj_stat = gss_import_sec_context(&min_stat, &sctx_tok, sctx);
                if (maj_stat != GSS_S_COMPLETE)
                    errx(1, "import server context failed: %s",
                         gssapi_err(maj_stat, min_stat, NULL));
                gss_release_buffer(&min_stat, &sctx_tok);
            }

            maj_stat = gss_accept_sec_context(&min_stat, sctx,
                                              GSS_C_NO_CREDENTIAL, &tmp,
                                              a_channel_bindings_p, &src_name,
                                              &actual_mech_server,
                                              &input_token, &ret_sflags,
                                              NULL, deleg_cred);
            if (GSS_ERROR(maj_stat))
                errx(1, "accept_sec_context: %s",
                     gssapi_err(maj_stat, min_stat, actual_mech_server));
            offset += tmp.length;
            if (maj_stat & GSS_S_CONTINUE_NEEDED)
                gss_release_name(&min_stat, &src_name);
            else
                server_done = 1;

            if (ei_ctx_flag && !server_done) {
                maj_stat = gss_export_sec_context(&min_stat, sctx, &sctx_tok);
                if (maj_stat != GSS_S_COMPLETE)
                    errx(1, "export server context failed: %s",
                         gssapi_err(maj_stat, min_stat, NULL));
                if (*sctx != GSS_C_NO_CONTEXT)
                    errx(1, "export server context did not release it");
            }

            gsskrb5_get_time_offset(&server_time_offset);

            if (output_token.length == offset)
                gss_release_buffer(&min_stat, &output_token);
        }
        if (verbose_flag)
            printf("loop #%d: end\n", num_loops);
    }
    if (output_token.length != 0)
	gss_release_buffer(&min_stat, &output_token);
    if (input_token.length != 0)
	gss_release_buffer(&min_stat, &input_token);
    gss_release_name(&min_stat, &gss_target_name);

    if (deleg_flag || policy_deleg_flag) {
	if (server_no_deleg_flag) {
	    if (*deleg_cred != GSS_C_NO_CREDENTIAL)
		errx(1, "got delegated cred but didn't expect one");
	} else if (*deleg_cred == GSS_C_NO_CREDENTIAL)
	    errx(1, "asked for delegarated cred but did get one");
    } else if (*deleg_cred != GSS_C_NO_CREDENTIAL)
	  errx(1, "got deleg_cred cred but didn't ask");

    if (gss_oid_equal(actual_mech_server, actual_mech_client) == 0)
	errx(1, "mech mismatch");
    *actual_mech = actual_mech_server;

    if (on_behalf_of_string) {
        gss_buffer_desc attr, value;

        attr.value =
            GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "authz-data#580";
        attr.length =
            sizeof(GSS_KRB5_NAME_ATTRIBUTE_BASE_URN "authz-data#580") - 1;
        maj_stat = gss_get_name_attribute(&min_stat, src_name, &attr, NULL,
                                          NULL, &value, NULL, NULL);
        if (maj_stat != GSS_S_COMPLETE)
            errx(1, "gss_get_name_attribute(authz-data#580) failed with %s",
                 gssapi_err(maj_stat, min_stat, GSS_KRB5_MECHANISM));

        if (value.length != strlen(on_behalf_of_string) ||
            strncmp(value.value, on_behalf_of_string,
                    strlen(on_behalf_of_string)) != 0)
            errx(1, "AD-ON-BEHALF-OF did not match");
        (void) gss_release_buffer(&min_stat, &value);
    }
    if (localname_string) {
        gss_buffer_desc lname;

        maj_stat = gss_localname(&min_stat, src_name, GSS_C_NO_OID, &lname);
        if (maj_stat != GSS_S_COMPLETE)
            errx(1, "localname: %s",
                 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
        if (verbose_flag)
            printf("localname: %.*s\n", (int)lname.length,
                   (char *)lname.value);
        if (lname.length != strlen(localname_string) ||
            strncmp(localname_string, lname.value, lname.length) != 0)
            errx(1, "localname: expected \"%s\", got \"%.*s\" (1)",
                 localname_string, (int)lname.length, (char *)lname.value);
        gss_release_buffer(&min_stat, &lname);
        maj_stat = gss_localname(&min_stat, src_name, actual_mech_server,
                                 &lname);
        if (maj_stat != GSS_S_COMPLETE)
            errx(1, "localname: %s",
                 gssapi_err(maj_stat, min_stat, actual_mech_server));
        if (lname.length != strlen(localname_string) ||
            strncmp(localname_string, lname.value, lname.length) != 0)
            errx(1, "localname: expected \"%s\", got \"%.*s\" (2)",
                 localname_string, (int)lname.length, (char *)lname.value);
        gss_release_buffer(&min_stat, &lname);

        if (!gss_userok(src_name, localname_string))
            errx(1, "localname is not userok");
        if (gss_userok(src_name, "nosuchuser:no"))
            errx(1, "gss_userok() appears broken");
    }
    if (verbose_flag) {
        gss_buffer_desc iname;

        maj_stat = gss_display_name(&min_stat, src_name, &iname, NULL);
        if (maj_stat == GSS_S_COMPLETE) {
            printf("client name: %.*s\n", (int)iname.length,
                (char *)iname.value);
            gss_release_buffer(&min_stat, &iname);
        } else
            warnx("display_name: %s",
                 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
	if (!anon_flag &&
	    gss_oid_equal(actual_mech_server, GSS_KRB5_MECHANISM))
	    show_pac_client_info(src_name);
    }
    gss_release_name(&min_stat, &src_name);

    if (max_loops && num_loops > max_loops)
	errx(1, "num loops %d was lager then max loops %d",
	     num_loops, max_loops);

    if (verbose_flag) {
	printf("server time offset: %d\n", server_time_offset);
	printf("client time offset: %d\n", client_time_offset);
	printf("num loops %d\n", num_loops);
	printf("cflags: ");
	if (ret_cflags & GSS_C_DELEG_FLAG)
	    printf("deleg ");
	if (ret_cflags & GSS_C_MUTUAL_FLAG)
	    printf("mutual ");
	if (ret_cflags & GSS_C_REPLAY_FLAG)
	    printf("replay ");
	if (ret_cflags & GSS_C_SEQUENCE_FLAG)
	    printf("sequence ");
	if (ret_cflags & GSS_C_CONF_FLAG)
	    printf("conf ");
	if (ret_cflags & GSS_C_INTEG_FLAG)
	    printf("integ ");
	if (ret_cflags & GSS_C_ANON_FLAG)
	    printf("anon ");
	if (ret_cflags & GSS_C_PROT_READY_FLAG)
	    printf("prot-ready ");
	if (ret_cflags & GSS_C_TRANS_FLAG)
	    printf("trans ");
	if (ret_cflags & GSS_C_DCE_STYLE)
	    printf("dce-style ");
	if (ret_cflags & GSS_C_IDENTIFY_FLAG)
	    printf("identify " );
	if (ret_cflags & GSS_C_EXTENDED_ERROR_FLAG)
	    printf("extended-error " );
	if (ret_cflags & GSS_C_DELEG_POLICY_FLAG)
	    printf("deleg-policy " );
	printf("\n");
	printf("sflags: ");
	if (ret_sflags & GSS_C_CHANNEL_BOUND_FLAG)
	    printf("channel-bound " );
	printf("\n");
    }
}

static void
wrapunwrap(gss_ctx_id_t cctx, gss_ctx_id_t sctx, int flags, gss_OID mechoid)
{
    gss_buffer_desc input_token, output_token, output_token2;
    OM_uint32 min_stat, maj_stat;
    gss_qop_t qop_state;
    int conf_state;

    input_token.value = "foo";
    input_token.length = 3;

    maj_stat = gss_wrap(&min_stat, cctx, flags, 0, &input_token,
			&conf_state, &output_token);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_wrap failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));

    maj_stat = gss_unwrap(&min_stat, sctx, &output_token,
			  &output_token2, &conf_state, &qop_state);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_unwrap failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));

    gss_release_buffer(&min_stat, &output_token);
    gss_release_buffer(&min_stat, &output_token2);

#if 0 /* doesn't work for NTLM yet */
    if (!!conf_state != !!flags)
	errx(1, "conf_state mismatch");
#endif
}

#define USE_CONF		1
#define USE_HEADER_ONLY		2
#define USE_SIGN_ONLY		4
#define FORCE_IOV		8
/* NO_DATA comes from <netdb.h>; we don't use it here; we appropriate it */
#ifdef NO_DATA
#undef NO_DATA
#endif
#define NO_DATA			16

static void
wrapunwrap_iov(gss_ctx_id_t cctx, gss_ctx_id_t sctx, int flags, gss_OID mechoid)
{
    krb5_data token, header, trailer;
    OM_uint32 min_stat, maj_stat;
    gss_qop_t qop_state;
    int conf_state, conf_state2;
    gss_iov_buffer_desc iov[6];
    unsigned char *p;
    int iov_len;
    char header_data[9] = "ABCheader";
    char trailer_data[10] = "trailerXYZ";

    char token_data[16] = "0123456789abcdef";

    memset(&iov, 0, sizeof(iov));

    if (flags & USE_SIGN_ONLY) {
	header.data = header_data;
	header.length = 9;
	trailer.data = trailer_data;
	trailer.length = 10;
    } else {
	header.data = NULL;
	header.length = 0;
	trailer.data = NULL;
	trailer.length = 0;
    }

    token.data = token_data;
    token.length = 16;

    iov_len = sizeof(iov)/sizeof(iov[0]);

    memset(iov, 0, sizeof(iov));

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;

    if (header.length != 0) {
	iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
	iov[1].buffer.length = header.length;
	iov[1].buffer.value = header.data;
    } else {
	iov[1].type = GSS_IOV_BUFFER_TYPE_EMPTY;
	iov[1].buffer.length = 0;
	iov[1].buffer.value = NULL;
    }
    iov[2].type = GSS_IOV_BUFFER_TYPE_DATA;
    if (flags & NO_DATA) {
	iov[2].buffer.length = 0;
    } else {
	iov[2].buffer.length = token.length;
    }
    iov[2].buffer.value = token.data;
    if (trailer.length != 0) {
	iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
	iov[3].buffer.length = trailer.length;
	iov[3].buffer.value = trailer.data;
    } else {
	iov[3].type = GSS_IOV_BUFFER_TYPE_EMPTY;
	iov[3].buffer.length = 0;
	iov[3].buffer.value = NULL;
    }
    if (dce_style_flag) {
	iov[4].type = GSS_IOV_BUFFER_TYPE_EMPTY;
    } else {
	iov[4].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    }
    iov[4].buffer.length = 0;
    iov[4].buffer.value = 0;
    if (dce_style_flag) {
	iov[5].type = GSS_IOV_BUFFER_TYPE_EMPTY;
    } else if (flags & USE_HEADER_ONLY) {
	iov[5].type = GSS_IOV_BUFFER_TYPE_EMPTY;
    } else {
	iov[5].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    }
    iov[5].buffer.length = 0;
    iov[5].buffer.value = 0;

    maj_stat = gss_wrap_iov(&min_stat, cctx, dce_style_flag || flags & USE_CONF, 0, &conf_state,
			    iov, iov_len);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_wrap_iov failed");

    token.length =
	iov[0].buffer.length +
	iov[1].buffer.length +
	iov[2].buffer.length +
	iov[3].buffer.length +
	iov[4].buffer.length +
	iov[5].buffer.length;
    token.data = emalloc(token.length);

    p = token.data;

    if (iov[0].buffer.length)
        memcpy(p, iov[0].buffer.value, iov[0].buffer.length);
    p += iov[0].buffer.length;

    if (iov[1].buffer.length)
        memcpy(p, iov[1].buffer.value, iov[1].buffer.length);
    p += iov[1].buffer.length;

    if (iov[2].buffer.length)
        memcpy(p, iov[2].buffer.value, iov[2].buffer.length);
    p += iov[2].buffer.length;

    if (iov[3].buffer.length)
        memcpy(p, iov[3].buffer.value, iov[3].buffer.length);
    p += iov[3].buffer.length;

    if (iov[4].buffer.length)
        memcpy(p, iov[4].buffer.value, iov[4].buffer.length);
    p += iov[4].buffer.length;

    if (iov[5].buffer.length)
        memcpy(p, iov[5].buffer.value, iov[5].buffer.length);
    p += iov[5].buffer.length;

    assert(p - ((unsigned char *)token.data) == token.length);

    if ((flags & (USE_SIGN_ONLY|FORCE_IOV)) == 0) {
	gss_buffer_desc input, output;

	input.value = token.data;
	input.length = token.length;

	maj_stat = gss_unwrap(&min_stat, sctx, &input,
			      &output, &conf_state2, &qop_state);

	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_unwrap from gss_wrap_iov failed: %s",
		 gssapi_err(maj_stat, min_stat, mechoid));

	gss_release_buffer(&min_stat, &output);
    } else {
	maj_stat = gss_unwrap_iov(&min_stat, sctx, &conf_state2, &qop_state,
				  iov, iov_len);

	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_unwrap_iov failed: %x %s", flags,
		 gssapi_err(maj_stat, min_stat, mechoid));

    }
    if (conf_state2 != conf_state)
	errx(1, "conf state wrong for iov: %x", flags);

    gss_release_iov_buffer(&min_stat, iov, iov_len);

    free(token.data);
}

static void
wrapunwrap_aead(gss_ctx_id_t cctx, gss_ctx_id_t sctx, int flags, gss_OID mechoid)
{
    gss_buffer_desc token, assoc, message = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output;
    OM_uint32 min_stat, maj_stat;
    gss_qop_t qop_state;
    int conf_state, conf_state2;
    char assoc_data[9] = "ABCheader";
    char token_data[16] = "0123456789abcdef";

    if (flags & USE_SIGN_ONLY) {
	assoc.value = assoc_data;
	assoc.length = 9;
    } else {
	assoc.value = NULL;
	assoc.length = 0;
    }

    token.value = token_data;
    token.length = 16;

    maj_stat = gss_wrap_aead(&min_stat, cctx, dce_style_flag || flags & USE_CONF,
			     GSS_C_QOP_DEFAULT, &assoc, &token,
			     &conf_state, &message);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_wrap_aead failed");

    if ((flags & (USE_SIGN_ONLY|FORCE_IOV)) == 0) {
	maj_stat = gss_unwrap(&min_stat, sctx, &message,
			      &output, &conf_state2, &qop_state);

	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_unwrap from gss_wrap_aead failed: %s",
		 gssapi_err(maj_stat, min_stat, mechoid));
    } else {
	maj_stat = gss_unwrap_aead(&min_stat, sctx, &message, &assoc,
				   &output, &conf_state2, &qop_state);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_unwrap_aead failed: %x %s", flags,
		 gssapi_err(maj_stat, min_stat, mechoid));
    }

    if (output.length != token.length)
	errx(1, "plaintext length wrong for aead");
    else if (memcmp(output.value, token.value, token.length) != 0)
	errx(1, "plaintext wrong for aead");
    if (conf_state2 != conf_state)
	errx(1, "conf state wrong for aead: %x", flags);

    gss_release_buffer(&min_stat, &message);
    gss_release_buffer(&min_stat, &output);
}

static void
getverifymic(gss_ctx_id_t cctx, gss_ctx_id_t sctx, gss_OID mechoid)
{
    gss_buffer_desc input_token, output_token;
    OM_uint32 min_stat, maj_stat;
    gss_qop_t qop_state;

    input_token.value = "bar";
    input_token.length = 3;

    maj_stat = gss_get_mic(&min_stat, cctx, 0, &input_token,
			   &output_token);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_get_mic failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));

    maj_stat = gss_verify_mic(&min_stat, sctx, &input_token,
			      &output_token, &qop_state);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_verify_mic failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));

    gss_release_buffer(&min_stat, &output_token);
}

static void
empty_release(void)
{
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_name_t name = GSS_C_NO_NAME;
    gss_OID_set oidset = GSS_C_NO_OID_SET;
    OM_uint32 junk;

    gss_delete_sec_context(&junk, &ctx, NULL);
    gss_release_cred(&junk, &cred);
    gss_release_name(&junk, &name);
    gss_release_oid_set(&junk, &oidset);
}

/*
 *
 */

static struct getargs args[] = {
    {"name-type",0,	arg_string, &type_string,  "type of name", NULL },
    {"mech-type",0,	arg_string, &mech_string,  "mech type (name)", NULL },
    {"mech-types",0,	arg_string, &mechs_string, "mech types (names)", NULL },
    {"ret-mech-type",0,	arg_string, &ret_mech_string,
     "type of return mech", NULL },
    {"dns-canonicalize",0,arg_negative_flag, &dns_canon_flag,
     "use dns to canonicalize", NULL },
    {"mutual-auth",0,	arg_flag,	&mutual_auth_flag,"mutual auth", NULL },
    {"client-ccache",0, arg_string,	&client_ccache, "client credentials cache", NULL },
    {"client-keytab",0, arg_string,	&client_keytab, "client keytab", NULL },
    {"client-name", 0,  arg_string,     &client_name, "client name", NULL },
    {"client-password", 0,  arg_string, &client_password, "client password", NULL },
    {"anonymous", 0,	arg_flag,	&anon_flag, "anonymous auth", NULL },
    {"i-channel-bindings", 0, arg_string, &i_channel_bindings, "initiator channel binding data", NULL },
    {"a-channel-bindings", 0, arg_string, &a_channel_bindings, "acceptor channel binding data", NULL },
    {"limit-enctype",0,	arg_string,	&limit_enctype_string, "enctype", NULL },
    {"dce-style",0,	arg_flag,	&dce_style_flag, "dce-style", NULL },
    {"wrapunwrap",0,	arg_flag,	&wrapunwrap_flag, "wrap/unwrap", NULL },
    {"iov", 0, 		arg_flag,	&iov_flag, "wrap/unwrap iov", NULL },
    {"aead", 0, 	arg_flag,	&aead_flag, "wrap/unwrap aead", NULL },
    {"getverifymic",0,	arg_flag,	&getverifymic_flag,
     "get and verify mic", NULL },
    {"delegate",0,	arg_flag,	&deleg_flag, "delegate credential", NULL },
    {"policy-delegate",0,	arg_flag,	&policy_deleg_flag, "policy delegate credential", NULL },
    {"server-no-delegate",0,	arg_flag,	&server_no_deleg_flag,
     "server should get a credential", NULL },
    {"export-import-context",0,	arg_flag,	&ei_ctx_flag, "test export/import context", NULL },
    {"export-import-cred",0,	arg_flag,	&ei_cred_flag, "test export/import cred", NULL },
    {"localname",0,     arg_string, &localname_string, "expected localname for client", "USERNAME"},
    {"gsskrb5-acceptor-identity", 0, arg_string, &gsskrb5_acceptor_identity, "keytab", NULL },
    {"session-enctype",	0, arg_string,	&session_enctype_string, "enctype", NULL },
    {"client-time-offset",	0, arg_integer,	&client_time_offset, "time", NULL },
    {"server-time-offset",	0, arg_integer,	&server_time_offset, "time", NULL },
    {"max-loops",	0, arg_integer,	&max_loops, "time", NULL },
    {"token-split",	0, arg_integer, &token_split, "bytes", NULL },
    {"on-behalf-of",	0, arg_string, &on_behalf_of_string, "principal",
        "send authenticator authz-data AD-ON-BEHALF-OF" },
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"verbose",	'v',	arg_flag,	&verbose_flag, "verbose", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "service@host");
    exit (ret);
}

int
main(int argc, char **argv)
{
    int optidx = 0;
    OM_uint32 min_stat, maj_stat;
    gss_ctx_id_t cctx, sctx;
    void *ctx;
    gss_OID nameoid, mechoid, actual_mech, actual_mech2;
    gss_cred_id_t client_cred = GSS_C_NO_CREDENTIAL, deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t cname = GSS_C_NO_NAME;
    gss_buffer_desc credential_data = GSS_C_EMPTY_BUFFER;
    gss_OID_desc oids[7];
    gss_OID_set_desc mechoid_descs;
    gss_OID_set mechoids = GSS_C_NO_OID_SET;
    gss_key_value_element_desc client_cred_elements[2];
    gss_key_value_set_desc client_cred_store;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;

    setprogname(argv[0]);

    if (krb5_init_context(&context))
	errx(1, "krb5_init_context");

    cctx = sctx = GSS_C_NO_CONTEXT;

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optidx;
    argv += optidx;

    if (argc != 1)
	usage(1);

    if (dns_canon_flag != -1)
	gsskrb5_set_dns_canonicalize(dns_canon_flag);

    if (type_string == NULL)
	nameoid = GSS_C_NT_HOSTBASED_SERVICE;
    else if (strcmp(type_string, "hostbased-service") == 0)
	nameoid = GSS_C_NT_HOSTBASED_SERVICE;
    else if (strcmp(type_string, "krb5-principal-name") == 0)
	nameoid = GSS_KRB5_NT_PRINCIPAL_NAME;
    else
	errx(1, "%s not supported", type_string);

    if (mech_string == NULL)
	mechoid = GSS_KRB5_MECHANISM;
    else
	mechoid = string_to_oid(mech_string);

    if (mechs_string == NULL) {
        /*
         * We ought to be able to use the OID set of the one mechanism
         * OID given.  But there's some breakage that conspires to make
         * that fail though it should succeed:
         *
         *  - the NTLM gss_acquire_cred() refuses to work with
         *    desired_name == GSS_C_NO_NAME
         *  - gss_acquire_cred() with desired_mechs == GSS_C_NO_OID_SET
         *    does work here because we happen to have Kerberos
         *    credentials in check-ntlm, and the subsequent
         *    gss_init_sec_context() call finds no cred element for NTLM
         *    but plows on anyways, surprisingly enough, and then the
         *    NTLM gss_init_sec_context() just works.
         *
         * In summary, there's some breakage in gss_init_sec_context()
         * and some breakage in NTLM that conspires against us here.
         *
         * We work around this in check-ntlm and check-spnego by adding
         * --client-name=user1@${R} to the invocations of this test
         * program that require it.
         */
        oids[0] = *mechoid;
        mechoid_descs.elements = &oids[0];
        mechoid_descs.count = 1;
        mechoids = &mechoid_descs;
    } else {
        string_to_oids(&mechoids, mechs_string);
    }

    if (gsskrb5_acceptor_identity) {
	/* XXX replace this with cred store, but test suites will need work */
	maj_stat = gsskrb5_register_acceptor_identity(gsskrb5_acceptor_identity);
	if (maj_stat)
	    errx(1, "gsskrb5_acceptor_identity: %s",
		 gssapi_err(maj_stat, 0, GSS_C_NO_OID));
    }

    if (client_password && (client_ccache || client_keytab)) {
	errx(1, "password option mutually exclusive with ccache or keytab option");
    }

    if (client_password) {
	credential_data.value = client_password;
	credential_data.length = strlen(client_password);
    }

    client_cred_store.count = 0;
    client_cred_store.elements = client_cred_elements;

    if (client_ccache) {
	client_cred_store.elements[client_cred_store.count].key = "ccache";
	client_cred_store.elements[client_cred_store.count].value = client_ccache;

	client_cred_store.count++;
    }

    if (client_keytab) {
	client_cred_store.elements[client_cred_store.count].key = "client_keytab";
	client_cred_store.elements[client_cred_store.count].value = client_keytab;

	client_cred_store.count++;
    }

    if (client_name) {
	gss_buffer_desc cn;

	cn.value = client_name;
	cn.length = strlen(client_name);

	maj_stat = gss_import_name(&min_stat, &cn, GSS_C_NT_USER_NAME, &cname);
	if (maj_stat)
	    errx(1, "gss_import_name: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    }

    if (client_password) {
	maj_stat = gss_acquire_cred_with_password(&min_stat,
						  cname,
						  &credential_data,
						  GSS_C_INDEFINITE,
						  mechoids,
						  GSS_C_INITIATE,
						  &client_cred,
						  &actual_mechs,
						  NULL);
	if (GSS_ERROR(maj_stat)) {
            if (mechoids != GSS_C_NO_OID_SET && mechoids->count == 1)
                mechoid = &mechoids->elements[0];
            else
                mechoid = GSS_C_NO_OID;
	    errx(1, "gss_acquire_cred_with_password: %s",
		 gssapi_err(maj_stat, min_stat, mechoid));
        }
    } else {
	maj_stat = gss_acquire_cred_from(&min_stat,
					 cname,
					 GSS_C_INDEFINITE,
					 mechoids,
					 GSS_C_INITIATE,
					 client_cred_store.count ? &client_cred_store
								 : GSS_C_NO_CRED_STORE,
					 &client_cred,
					 &actual_mechs,
					 NULL);
	if (GSS_ERROR(maj_stat) && !anon_flag)
	    errx(1, "gss_acquire_cred: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    }

    gss_release_name(&min_stat, &cname);

    if (verbose_flag) {
	size_t i;

	printf("cred mechs:");
	for (i = 0; i < actual_mechs->count; i++)
	    printf(" %s", gss_oid_to_name(&actual_mechs->elements[i]));
	printf("\n");
    }

    if (gss_oid_equal(mechoid, GSS_SPNEGO_MECHANISM) && mechs_string) {
	maj_stat = gss_set_neg_mechs(&min_stat, client_cred, mechoids);
	if (GSS_ERROR(maj_stat))
	    errx(1, "gss_set_neg_mechs: %s",
		 gssapi_err(maj_stat, min_stat, GSS_SPNEGO_MECHANISM));

        mechoid_descs.elements = GSS_SPNEGO_MECHANISM;
        mechoid_descs.count = 1;
        mechoids = &mechoid_descs;
    }

    if (ei_cred_flag) {
	gss_cred_id_t cred2 = GSS_C_NO_CREDENTIAL;
	gss_buffer_desc cb;

	maj_stat = gss_export_cred(&min_stat, client_cred, &cb);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "export cred failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	maj_stat = gss_import_cred(&min_stat, &cb, &cred2);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "import cred failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	gss_release_buffer(&min_stat, &cb);
	gss_release_cred(&min_stat, &client_cred);
	client_cred = cred2;
    }

    if (limit_enctype_string) {
	krb5_error_code ret;

	ret = krb5_string_to_enctype(context,
				     limit_enctype_string,
				     &limit_enctype);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_string_to_enctype");
    }


    if (limit_enctype) {
	if (client_cred == NULL)
	    errx(1, "client_cred missing");

	maj_stat = gss_krb5_set_allowable_enctypes(&min_stat, client_cred,
						   1, &limit_enctype);
	if (maj_stat)
	    errx(1, "gss_krb5_set_allowable_enctypes: %s",
		 gssapi_err(maj_stat, min_stat, GSS_C_NO_OID));
    }

    loop(mechoid, nameoid, argv[0], client_cred,
	 &sctx, &cctx, &actual_mech, &deleg_cred);

    if (verbose_flag)
	printf("resulting mech: %s\n", gss_oid_to_name(actual_mech));

    if (ret_mech_string) {
	gss_OID retoid;

	retoid = string_to_oid(ret_mech_string);

	if (gss_oid_equal(retoid, actual_mech) == 0)
	    errx(1, "actual_mech mech is not the expected type %s",
		 ret_mech_string);
    }

    /* XXX should be actual_mech */
    if (gss_oid_equal(mechoid, GSS_KRB5_MECHANISM)) {
	time_t sc_time;
	gss_buffer_desc authz_data;
	gss_buffer_desc in, out1, out2;
	krb5_keyblock *keyblock, *keyblock2;
	krb5_timestamp now;
	krb5_error_code ret;

	ret = krb5_timeofday(context, &now);
	if (ret)
	    errx(1, "krb5_timeofday failed");

	/* client */
	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat,
						     &cctx,
						     1, /* version */
						     &ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_export_lucid_sec_context failed: %s",
		 gssapi_err(maj_stat, min_stat, actual_mech));


	maj_stat = gss_krb5_free_lucid_sec_context(&maj_stat, ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_free_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	/* server */
	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat,
						     &sctx,
						     1, /* version */
						     &ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_export_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));
	maj_stat = gss_krb5_free_lucid_sec_context(&min_stat, ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_free_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

 	maj_stat = gsskrb5_extract_authtime_from_sec_context(&min_stat,
							     sctx,
							     &sc_time);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gsskrb5_extract_authtime_from_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	if (sc_time > now)
	    errx(1, "gsskrb5_extract_authtime_from_sec_context failed: "
		 "time authtime is before now: %ld %ld",
		 (long)sc_time, (long)now);

 	maj_stat = gsskrb5_extract_service_keyblock(&min_stat,
						    sctx,
						    &keyblock);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gsskrb5_export_service_keyblock failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	krb5_free_keyblock(context, keyblock);

 	maj_stat = gsskrb5_get_subkey(&min_stat,
				      sctx,
				      &keyblock);
	if (maj_stat != GSS_S_COMPLETE
	    && (!(maj_stat == GSS_S_FAILURE && min_stat == GSS_KRB5_S_KG_NO_SUBKEY)))
	    errx(1, "gsskrb5_get_subkey server failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	if (maj_stat != GSS_S_COMPLETE)
	    keyblock = NULL;
	else if (limit_enctype && keyblock->keytype != limit_enctype)
	    errx(1, "gsskrb5_get_subkey wrong enctype");

 	maj_stat = gsskrb5_get_subkey(&min_stat,
				      cctx,
				      &keyblock2);
	if (maj_stat != GSS_S_COMPLETE
	    && (!(maj_stat == GSS_S_FAILURE && min_stat == GSS_KRB5_S_KG_NO_SUBKEY)))
	    errx(1, "gsskrb5_get_subkey client failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	if (maj_stat != GSS_S_COMPLETE)
	    keyblock2 = NULL;
	else if (limit_enctype && keyblock && keyblock->keytype != limit_enctype)
	    errx(1, "gsskrb5_get_subkey wrong enctype");

	if (keyblock || keyblock2) {
	    if (keyblock == NULL)
		errx(1, "server missing token keyblock");
	    if (keyblock2 == NULL)
		errx(1, "client missing token keyblock");

	    if (keyblock->keytype != keyblock2->keytype)
		errx(1, "enctype mismatch");
	    if (keyblock->keyvalue.length != keyblock2->keyvalue.length)
		errx(1, "key length mismatch");
	    if (memcmp(keyblock->keyvalue.data, keyblock2->keyvalue.data,
		       keyblock2->keyvalue.length) != 0)
		errx(1, "key data mismatch");
	}

	if (session_enctype_string) {
	    krb5_enctype enctype;

	    ret = krb5_string_to_enctype(context,
					 session_enctype_string,
					 &enctype);

	    if (ret)
		krb5_err(context, 1, ret, "krb5_string_to_enctype");

	    if (keyblock && enctype != keyblock->keytype)
		errx(1, "keytype is not the expected %d != %d",
		     (int)enctype, (int)keyblock2->keytype);
	}

	if (keyblock)
	    krb5_free_keyblock(context, keyblock);
	if (keyblock2)
	    krb5_free_keyblock(context, keyblock2);

 	maj_stat = gsskrb5_get_initiator_subkey(&min_stat,
						sctx,
						&keyblock);
	if (maj_stat != GSS_S_COMPLETE
	    && (!(maj_stat == GSS_S_FAILURE && min_stat == GSS_KRB5_S_KG_NO_SUBKEY)))
	    errx(1, "gsskrb5_get_initiator_subkey failed: %s",
		     gssapi_err(maj_stat, min_stat, actual_mech));

	if (maj_stat == GSS_S_COMPLETE) {

	    if (limit_enctype && keyblock->keytype != limit_enctype)
		errx(1, "gsskrb5_get_initiator_subkey wrong enctype");
	    krb5_free_keyblock(context, keyblock);
	}

 	maj_stat = gsskrb5_extract_authz_data_from_sec_context(&min_stat,
							       sctx,
							       128,
							       &authz_data);
	if (maj_stat == GSS_S_COMPLETE)
	    gss_release_buffer(&min_stat, &authz_data);


	memset(&out1, 0, sizeof(out1));
	memset(&out2, 0, sizeof(out2));

	in.value = "foo";
	in.length = 3;

	gss_pseudo_random(&min_stat, sctx, GSS_C_PRF_KEY_FULL, &in,
			  100, &out1);
	gss_pseudo_random(&min_stat, cctx, GSS_C_PRF_KEY_FULL, &in,
			  100, &out2);

	if (out1.length != out2.length)
	    errx(1, "prf len mismatch");
	if (out1.length && memcmp(out1.value, out2.value, out1.length) != 0)
	    errx(1, "prf data mismatch");

	gss_release_buffer(&min_stat, &out1);

	gss_pseudo_random(&min_stat, sctx, GSS_C_PRF_KEY_FULL, &in,
			  100, &out1);

	if (out1.length != out2.length)
	    errx(1, "prf len mismatch");
	if (out1.length && memcmp(out1.value, out2.value, out1.length) != 0)
	    errx(1, "prf data mismatch");

	gss_release_buffer(&min_stat, &out1);
	gss_release_buffer(&min_stat, &out2);

	in.value = "bar";
	in.length = 3;

	gss_pseudo_random(&min_stat, sctx, GSS_C_PRF_KEY_PARTIAL, &in,
			  100, &out1);
	gss_pseudo_random(&min_stat, cctx, GSS_C_PRF_KEY_PARTIAL, &in,
			  100, &out2);

	if (out1.length != out2.length)
	    errx(1, "prf len mismatch");
	if (memcmp(out1.value, out2.value, out1.length) != 0)
	    errx(1, "prf data mismatch");

	gss_release_buffer(&min_stat, &out1);
	gss_release_buffer(&min_stat, &out2);

	wrapunwrap_flag = 1;
	getverifymic_flag = 1;
    }

    if (ei_ctx_flag) {
	gss_buffer_desc ctx_token = GSS_C_EMPTY_BUFFER;

	maj_stat = gss_export_sec_context(&min_stat, &cctx, &ctx_token);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "export client context failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	if (cctx != GSS_C_NO_CONTEXT)
	    errx(1, "export client context did not release it");

	maj_stat = gss_import_sec_context(&min_stat, &ctx_token, &cctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "import client context failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	gss_release_buffer(&min_stat, &ctx_token);

	maj_stat = gss_export_sec_context(&min_stat, &sctx, &ctx_token);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "export server context failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	if (sctx != GSS_C_NO_CONTEXT)
	    errx(1, "export server context did not release it");

	maj_stat = gss_import_sec_context(&min_stat, &ctx_token, &sctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "import server context failed: %s",
		 gssapi_err(maj_stat, min_stat, NULL));

	gss_release_buffer(&min_stat, &ctx_token);
    }

    if (wrapunwrap_flag) {
	wrapunwrap(cctx, sctx, 0, actual_mech);
	wrapunwrap(cctx, sctx, 1, actual_mech);
	wrapunwrap(sctx, cctx, 0, actual_mech);
	wrapunwrap(sctx, cctx, 1, actual_mech);
    }

    if (iov_flag) {
	wrapunwrap_iov(cctx, sctx, 0, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_HEADER_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_HEADER_ONLY, actual_mech);

	wrapunwrap_iov(cctx, sctx, FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_HEADER_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_HEADER_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_SIGN_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_HEADER_ONLY|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

/* works */
	wrapunwrap_iov(cctx, sctx, 0, actual_mech);
	wrapunwrap_iov(cctx, sctx, FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_CONF, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_SIGN_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_SIGN_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_HEADER_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, USE_CONF|USE_HEADER_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_HEADER_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_HEADER_ONLY, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_HEADER_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_HEADER_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_SIGN_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_HEADER_ONLY|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

 /* works */
	wrapunwrap_iov(cctx, sctx, NO_DATA, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_SIGN_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_SIGN_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_HEADER_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_HEADER_ONLY, actual_mech);
	wrapunwrap_iov(cctx, sctx, NO_DATA|USE_CONF|USE_HEADER_ONLY|FORCE_IOV, actual_mech);
    }

    if (aead_flag) {
	wrapunwrap_aead(cctx, sctx, 0, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_CONF, actual_mech);

	wrapunwrap_aead(cctx, sctx, FORCE_IOV, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_CONF|FORCE_IOV, actual_mech);

	wrapunwrap_aead(cctx, sctx, USE_SIGN_ONLY|FORCE_IOV, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_aead(cctx, sctx, 0, actual_mech);
	wrapunwrap_aead(cctx, sctx, FORCE_IOV, actual_mech);

	wrapunwrap_aead(cctx, sctx, USE_CONF, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_CONF|FORCE_IOV, actual_mech);

	wrapunwrap_aead(cctx, sctx, USE_SIGN_ONLY, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_SIGN_ONLY|FORCE_IOV, actual_mech);

	wrapunwrap_aead(cctx, sctx, USE_CONF|USE_SIGN_ONLY, actual_mech);
	wrapunwrap_aead(cctx, sctx, USE_CONF|USE_SIGN_ONLY|FORCE_IOV, actual_mech);
    }

    if (getverifymic_flag) {
	getverifymic(cctx, sctx, actual_mech);
	getverifymic(cctx, sctx, actual_mech);
	getverifymic(sctx, cctx, actual_mech);
	getverifymic(sctx, cctx, actual_mech);
    }

    gss_delete_sec_context(&min_stat, &cctx, NULL);
    gss_delete_sec_context(&min_stat, &sctx, NULL);

    if (deleg_cred != GSS_C_NO_CREDENTIAL) {
	gss_cred_id_t cred2 = GSS_C_NO_CREDENTIAL;
	gss_buffer_desc cb;

	if (verbose_flag)
	    printf("checking actual mech (%s) on delegated cred\n",
		   gss_oid_to_name(actual_mech));
	loop(actual_mech, nameoid, argv[0], deleg_cred, &sctx, &cctx, &actual_mech2, &cred2);

	gss_delete_sec_context(&min_stat, &cctx, NULL);
	gss_delete_sec_context(&min_stat, &sctx, NULL);

	gss_release_cred(&min_stat, &cred2);

#if 0
        /*
         * XXX We can't do this.  Delegated credentials only work with
         * the actual_mech.  We could gss_store_cred the delegated
         * credentials *then* gss_add/acquire_cred() with SPNEGO, then
         * we could try loop() with those credentials.
         */
	/* try again using SPNEGO */
	if (verbose_flag)
	    printf("checking spnego on delegated cred\n");
	loop(GSS_SPNEGO_MECHANISM, nameoid, argv[0], deleg_cred, &sctx, &cctx,
	     &actual_mech2, &cred2);

	gss_delete_sec_context(&min_stat, &cctx, NULL);
	gss_delete_sec_context(&min_stat, &sctx, NULL);

	gss_release_cred(&min_stat, &cred2);
#endif

	/* check export/import */
	if (ei_cred_flag) {

	    maj_stat = gss_export_cred(&min_stat, deleg_cred, &cb);
	    if (maj_stat != GSS_S_COMPLETE)
		errx(1, "export cred failed: %s",
		     gssapi_err(maj_stat, min_stat, NULL));

	    maj_stat = gss_import_cred(&min_stat, &cb, &cred2);
	    if (maj_stat != GSS_S_COMPLETE)
		errx(1, "import cred failed: %s",
		     gssapi_err(maj_stat, min_stat, NULL));

	    gss_release_buffer(&min_stat, &cb);
	    gss_release_cred(&min_stat, &deleg_cred);

	    if (verbose_flag)
		printf("checking actual mech (%s) on export/imported cred\n",
		       gss_oid_to_name(actual_mech));
	    loop(actual_mech, nameoid, argv[0], cred2, &sctx, &cctx,
		 &actual_mech2, &deleg_cred);

	    gss_release_cred(&min_stat, &deleg_cred);

	    gss_delete_sec_context(&min_stat, &cctx, NULL);
	    gss_delete_sec_context(&min_stat, &sctx, NULL);

#if 0
            /* XXX See above */
	    /* try again using SPNEGO */
	    if (verbose_flag)
		printf("checking SPNEGO on export/imported cred\n");
	    loop(GSS_SPNEGO_MECHANISM, nameoid, argv[0], cred2, &sctx, &cctx,
		 &actual_mech2, &deleg_cred);

	    gss_release_cred(&min_stat, &deleg_cred);

	    gss_delete_sec_context(&min_stat, &cctx, NULL);
	    gss_delete_sec_context(&min_stat, &sctx, NULL);
#endif

	    gss_release_cred(&min_stat, &cred2);

	} else  {
	    gss_release_cred(&min_stat, &deleg_cred);
	}

    }

    gss_release_cred(&min_stat, &client_cred);
    gss_release_oid_set(&min_stat, &actual_mechs);
    if (mechoids != GSS_C_NO_OID_SET && mechoids != &mechoid_descs)
	gss_release_oid_set(&min_stat, &mechoids);
    empty_release();

    krb5_free_context(context);

    return 0;
}
