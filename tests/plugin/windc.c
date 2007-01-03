#include <krb5.h>
#include <hdb.h>
#include <windc_plugin.h>

static krb5_error_code
windc_init(krb5_context context, void **ctx)
{
    krb5_warnx(context, "windc init");
    *ctx = NULL;
    return 0;
}

static void
windc_fini(void *ctx)
{
}

static krb5_error_code 
pac_generate(void *ctx, krb5_context context,
	     struct hdb_entry_ex *client, krb5_pac *pac)
{
    krb5_error_code ret;
    krb5_data data;

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

static krb5_error_code 
pac_verify(void *ctx, krb5_context context,
	   struct hdb_entry_ex *client, krb5_pac pac)
{
    krb5_error_code ret;
    krb5_data data;

    ret = krb5_pac_get_buffer(context, pac, 1, &data);
    if (ret)
	return ret;

    krb5_data_free(&data);

    return 0;
}



krb5plugin_windc_ftable windc = {
    KRB5_WINDC_PLUGING_MINOR,
    windc_init,
    windc_fini,
    pac_generate,
    pac_verify
};
