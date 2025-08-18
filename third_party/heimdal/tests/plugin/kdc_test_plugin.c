#include <string.h>
#include <krb5_locl.h>
#include <hdb.h>
#include <hx509.h>
#include <kdc.h>
#include <kdc-plugin.h>

static krb5_error_code KRB5_CALLCONV
init(krb5_context context, void **ctx)
{
    krb5_warnx(context, "kdc plugin init");
    *ctx = NULL;
    return 0;
}

static void KRB5_CALLCONV
fini(void *ctx)
{
}

static krb5_error_code KRB5_CALLCONV
pac_generate(void *ctx,
	     astgs_request_t r,
	     hdb_entry *client,
	     hdb_entry *server,
	     const krb5_keyblock *pk_replykey,
	     uint64_t pac_attributes,
	     krb5_pac *pac)
{
    krb5_context context = kdc_request_get_context((kdc_request_t)r);
    krb5_error_code ret;
    krb5_data data;

    if ((pac_attributes & (KRB5_PAC_WAS_REQUESTED |
			   KRB5_PAC_WAS_GIVEN_IMPLICITLY)) == 0) {
	*pac = NULL;
	return 0;
    }

    krb5_warnx(context, "pac generate");

    data.data = "\x00\x01";
    data.length = 2;

    ret = krb5_pac_init(context, pac);
    if (ret)
	return ret;

    ret = krb5_pac_add_buffer(context, *pac, 1, &data);
    if (ret)
	return ret;

    return 0;
}

static krb5_error_code KRB5_CALLCONV
pac_verify(void *ctx,
	   astgs_request_t r,
	   krb5_const_principal new_ticket_client,
	   hdb_entry * delegation_proxy,
	   hdb_entry * client,
	   hdb_entry * server,
	   hdb_entry * krbtgt,
	   EncTicketPart *ticket,
	   krb5_pac pac)
{
    krb5_context context = kdc_request_get_context((kdc_request_t)r);
    krb5_error_code ret;
    krb5_data data;
    krb5_cksumtype cstype;
    uint16_t rodc_id;
    krb5_enctype etype;
    Key *key;

    krb5_warnx(context, "pac_verify");

    ret = krb5_pac_get_buffer(context, pac, 1, &data);
    if (ret)
	return ret;
    krb5_data_free(&data);

    ret = krb5_pac_get_kdc_checksum_info(context, pac, &cstype, &rodc_id);
    if (ret)
	return ret;

    if (rodc_id == 0 || rodc_id != krbtgt->kvno >> 16) {
	krb5_warnx(context, "Wrong RODCIdentifier");
	return EINVAL;
    }

    ret = krb5_cksumtype_to_enctype(context, cstype, &etype);
    if (ret)
	return ret;

    ret = hdb_enctype2key(context, krbtgt, NULL, etype, &key);
    if (ret)
	return ret;

    return krb5_pac_verify(context, pac, 0, NULL, NULL, &key->key);
}

static void logit(const char *what, astgs_request_t r)
{
    krb5_context context = kdc_request_get_context((kdc_request_t)r);
    const char *cname = kdc_request_get_cname((kdc_request_t)r);
    const char *sname = kdc_request_get_sname((kdc_request_t)r);

    krb5_warnx(context, "%s: client %s server %s",
	       what,
	       cname ? cname : "<unknown>",
	       sname ? sname : "<unknown>");
}

static krb5_error_code KRB5_CALLCONV
client_access(void *ctx, astgs_request_t r)
{
    logit("client_access", r);

    return 0;
}

static krb5_error_code KRB5_CALLCONV
finalize_reply(void *ctx, astgs_request_t r)
{
    heim_number_t n;
    krb5_error_code ret;

    logit("finalize_reply", r);

    n = heim_number_create(1234);
    if (n == NULL)
	return ENOMEM;

    ret = kdc_request_set_attribute((kdc_request_t)r,
				    HSTR("org.h5l.tests.kdc-plugin"), n);
    heim_release(n);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
audit(void *ctx, astgs_request_t r)
{
    krb5_error_code ret = kdc_request_get_error_code((kdc_request_t)r);
    heim_number_t n;

    logit("audit", r);

    if (ret)
	return 0; /* finalize_reply only called in success */

    n = kdc_request_get_attribute((kdc_request_t)r,
				  HSTR("org.h5l.tests.kdc-plugin"));

    heim_assert(n && heim_number_get_int(n) == 1234,
		"attribute not passed from finalize_reply");

    if (n == NULL || heim_number_get_int(n) != 1234)
	return EINVAL; /* return value is ignored, but for completeness */

    return 0;
}

static krb5plugin_kdc_ftable kdc_plugin = {
    KRB5_PLUGIN_KDC_VERSION_12,
    init,
    fini,
    pac_generate,
    pac_verify,
    NULL, /* pac_update */
    client_access,
    NULL, /* referral_policy */
    finalize_reply,
    audit
};

static const krb5plugin_kdc_ftable *const kdc_plugins[] = {
    &kdc_plugin
};

krb5_error_code KRB5_CALLCONV
kdc_plugin_load(krb5_context context,
	        krb5_get_instance_func_t *get_instance,
	        size_t *num_plugins,
		const krb5plugin_kdc_ftable *const **plugins);

static uintptr_t KRB5_CALLCONV
kdc_plugin_get_instance(const char *libname)
{
    if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}

krb5_error_code KRB5_CALLCONV
kdc_plugin_load(krb5_context context,
		krb5_get_instance_func_t *get_instance,
		size_t *num_plugins,
		const krb5plugin_kdc_ftable *const **plugins)
{
    *get_instance = kdc_plugin_get_instance;
    *num_plugins = sizeof(kdc_plugins) / sizeof(kdc_plugins[0]);
    *plugins = kdc_plugins;

    return 0;
}
