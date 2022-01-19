#include <string.h>
#include <krb5_locl.h>
#include <hdb.h>
#include <hx509.h>
#include <kdc.h>
#include <windc_plugin.h>

static krb5_error_code KRB5_CALLCONV
windc_init(krb5_context context, void **ctx)
{
    krb5_warnx(context, "windc init");
    *ctx = NULL;
    return 0;
}

static void KRB5_CALLCONV
windc_fini(void *ctx)
{
}

static krb5_error_code KRB5_CALLCONV
pac_generate(void *ctx, krb5_context context,
	     struct hdb_entry_ex *client,
	     struct hdb_entry_ex *server,
	     const krb5_keyblock *pk_replykey,
	     uint64_t pac_attributes,
	     krb5_pac *pac)
{
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
pac_verify(void *ctx, krb5_context context,
	   const krb5_principal new_ticket_client,
	   const krb5_principal delegation_proxy,
	   struct hdb_entry_ex * client,
	   struct hdb_entry_ex * server,
	   struct hdb_entry_ex * krbtgt,
	   krb5_pac *pac)
{
    krb5_error_code ret;
    krb5_data data;
    krb5_cksumtype cstype;
    uint16_t rodc_id;
    krb5_enctype etype;
    Key *key;

    krb5_warnx(context, "pac_verify");

    ret = krb5_pac_get_buffer(context, *pac, 1, &data);
    if (ret)
	return ret;
    krb5_data_free(&data);

    ret = krb5_pac_get_kdc_checksum_info(context, *pac, &cstype, &rodc_id);
    if (ret)
	return ret;

    if (rodc_id == 0 || rodc_id != krbtgt->entry.kvno >> 16) {
	krb5_warnx(context, "Wrong RODCIdentifier");
	return EINVAL;
    }

    ret = krb5_cksumtype_to_enctype(context, cstype, &etype);
    if (ret)
	return ret;

    ret = hdb_enctype2key(context, &krbtgt->entry, NULL, etype, &key);
    if (ret)
	return ret;

    return krb5_pac_verify(context, *pac, 0, NULL, NULL, &key->key);
}

static void logit(const char *what, astgs_request_t r)
{
    krb5_warnx(r->context, "%s: client %s server %s",
	       what,
	       r->cname ? r->cname : "<unknown>",
	       r->sname ? r->sname : "<unknown>");
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
    logit("finalize_reply", r);
    return 0;
}

static krb5plugin_windc_ftable windc = {
    KRB5_WINDC_PLUGING_MINOR,
    windc_init,
    windc_fini,
    pac_generate,
    pac_verify,
    client_access,
    finalize_reply
};

static const krb5plugin_windc_ftable *const windc_plugins[] = {
    &windc
};

krb5_error_code KRB5_CALLCONV
windc_plugin_load(krb5_context context,
		       krb5_get_instance_func_t *get_instance,
		       size_t *num_plugins,
		       const krb5plugin_windc_ftable *const **plugins);

static uintptr_t KRB5_CALLCONV
windc_get_instance(const char *libname)
{
    if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}

krb5_error_code KRB5_CALLCONV
windc_plugin_load(krb5_context context,
		  krb5_get_instance_func_t *get_instance,
		  size_t *num_plugins,
		  const krb5plugin_windc_ftable *const **plugins)
{
    *get_instance = windc_get_instance;
    *num_plugins = sizeof(windc_plugins) / sizeof(windc_plugins[0]);
    *plugins = windc_plugins;

    return 0;
}
