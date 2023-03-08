/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#include "kadmin-commands.h"

struct cpw_entry_data {
    int keepold;
    int random_key;
    int random_password;
    char *password;
    krb5_key_data *key_data;
    void *kadm_handle;
};

static int
set_random_key(void *dup_kadm_handle, krb5_principal principal, int keepold)
{
    krb5_error_code ret;
    int i;
    krb5_keyblock *keys;
    int num_keys;

    ret = kadm5_randkey_principal_3(dup_kadm_handle, principal, keepold, 0,
                                    NULL, &keys, &num_keys);
    if(ret)
	return ret;
    for(i = 0; i < num_keys; i++)
	krb5_free_keyblock_contents(context, &keys[i]);
    free(keys);
    return 0;
}

static int
set_random_password(void *dup_kadm_handle,
                    krb5_principal principal,
                    int keepold)
{
    krb5_error_code ret;
    char pw[128];
    char *princ_name;

    ret = krb5_unparse_name(context, principal, &princ_name);
    if (ret)
	return ret;

    random_password(pw, sizeof(pw));
    ret = kadm5_chpass_principal_3(dup_kadm_handle, principal, keepold, 0,
                                   NULL, pw);
    if (ret == 0)
	printf ("%s's password set to \"%s\"\n", princ_name, pw);
    free(princ_name);
    memset_s(pw, sizeof(pw), 0, sizeof(pw));
    return ret;
}

static int
set_password(void *dup_kadm_handle,
             krb5_principal principal,
             char *password,
             int keepold)
{
    krb5_error_code ret = 0;
    char pwbuf[128];
    int aret;

    if(password == NULL) {
	char *princ_name;
	char *prompt;

	ret = krb5_unparse_name(context, principal, &princ_name);
	if (ret)
	    return ret;
	aret = asprintf(&prompt, "%s's Password: ", princ_name);
	free (princ_name);
	if (aret == -1)
	    return ENOMEM;
	ret = UI_UTIL_read_pw_string(pwbuf, sizeof(pwbuf), prompt,
				     UI_UTIL_FLAG_VERIFY |
				     UI_UTIL_FLAG_VERIFY_SILENT);
	free (prompt);
	if(ret){
            return KRB5_LIBOS_BADPWDMATCH;
	}
	password = pwbuf;
    }
    if(ret == 0)
        ret = kadm5_chpass_principal_3(dup_kadm_handle, principal, keepold, 0,
                                       NULL, password);
    memset_s(pwbuf, sizeof(pwbuf), 0, sizeof(pwbuf));
    return ret;
}

static int
set_key_data(void *dup_kadm_handle,
             krb5_principal principal,
             krb5_key_data *key_data,
             int keepold)
{
    krb5_error_code ret;

    ret = kadm5_chpass_principal_with_key_3(dup_kadm_handle, principal, keepold,
					    3, key_data);
    return ret;
}

static int
do_cpw_entry(krb5_principal principal, void *data)
{
    struct cpw_entry_data *e = data;

    if (e->random_key)
	return set_random_key(e->kadm_handle, principal, e->keepold);
    else if (e->random_password)
	return set_random_password(e->kadm_handle, principal, e->keepold);
    else if (e->key_data)
	return set_key_data(e->kadm_handle, principal, e->key_data, e->keepold);
    else
	return set_password(e->kadm_handle, principal, e->password, e->keepold);
}

int
cpw_entry(struct passwd_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    int i;
    struct cpw_entry_data data;
    int num;
    int16_t n_key_data = 0;
    krb5_key_data key_data[3];

    memset(key_data, 0, sizeof(key_data));
    data.kadm_handle = NULL;
    ret = kadm5_dup_context(kadm_handle, &data.kadm_handle);
    if (ret)
        krb5_err(context, 1, ret, "Could not duplicate kadmin connection");
    data.random_key = opt->random_key_flag;
    data.random_password = opt->random_password_flag;
    data.password = opt->password_string;
    data.key_data	 = NULL;

    /*
     * --keepold is the the default, and it should mean "prune all old keys not
     * needed to decrypt extant tickets".
     */
    num = 0;
    data.keepold = 1;
    if (opt->keepold_flag) {
        data.keepold = 1;
        num++;
    }
    if (opt->keepallold_flag) {
        data.keepold = 2;
        num++;
    }
    if (opt->pruneall_flag) {
        data.keepold = 0;
        num++;
    }
    if (num > 1) {
        fprintf(stderr, "use only one of --keepold, --keepallold, and --pruneall\n");
        return 1;
    }

    num = 0;
    if (data.random_key)
	++num;
    if (data.random_password)
	++num;
    if (data.password)
	++num;
    if (opt->key_string)
	++num;

    if (num > 1) {
	fprintf (stderr, "give only one of "
		"--random-key, --random-password, --password, --key\n");
	return 1;
    }

    if (opt->key_string) {
	const char *error;

	if (parse_des_key (opt->key_string, key_data, &error)) {
	    fprintf (stderr, "failed parsing key \"%s\": %s\n",
		     opt->key_string, error);
	    return 1;
	}
        n_key_data = sizeof(key_data)/sizeof(key_data[0]);
	data.key_data = key_data;
    }

    for(i = 0; i < argc; i++)
	ret = foreach_principal(argv[i], do_cpw_entry, "cpw", &data);

    kadm5_destroy(data.kadm_handle);

    if (opt->key_string)
        kadm5_free_key_data(kadm_handle, &n_key_data, key_data);

    return ret != 0;
}
