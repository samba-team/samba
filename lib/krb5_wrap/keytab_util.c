/*
 * Copyright (c) 1997-2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Copyright (c) 2011 Andrew Bartlett
 *
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

#include "includes.h"
#include "krb5_samba.h"

static krb5_boolean
compare_keyblock(const krb5_keyblock *a, const krb5_keyblock *b)
{
    if (KRB5_KEY_TYPE(a) != KRB5_KEY_TYPE(b) ||
        KRB5_KEY_LENGTH(a) != KRB5_KEY_LENGTH(b) ||
        memcmp(KRB5_KEY_DATA(a), KRB5_KEY_DATA(b), KRB5_KEY_LENGTH(a)) != 0)
	return false;
    return true;
}

static krb5_error_code copy_one_entry(krb5_context context,
				      krb5_keytab src_keytab,
				      krb5_keytab dst_keytab,
				      krb5_keytab_entry entry)
{
    krb5_error_code ret;
    krb5_keytab_entry dummy;

    char *name_str;
    char *etype_str;
    ret = krb5_unparse_name (context, entry.principal, &name_str);
    if(ret) {
	krb5_set_error_message(context, ret, "krb5_unparse_name");
	name_str = NULL; /* XXX */
	return ret;
    }
    ret = smb_krb5_enctype_to_string(context,
					KRB5_KEY_TYPE(KRB5_KT_KEY(&entry)),
					&etype_str);
    if(ret) {
	krb5_set_error_message(context, ret, "krb5_enctype_to_string");
	etype_str = NULL; /* XXX */
	return ret;
    }
    ret = krb5_kt_get_entry(context, dst_keytab,
			    entry.principal,
			    entry.vno,
			    KRB5_KEY_TYPE(KRB5_KT_KEY(&entry)),
			    &dummy);
    if(ret == 0) {
	/* this entry is already in the new keytab, so no need to
	   copy it; if the keyblocks are not the same, something
	   is weird, so complain about that */
	if (!compare_keyblock(KRB5_KT_KEY(&entry), KRB5_KT_KEY(&dummy))) {
		DEBUG(2, ("copy_one_entry: entry with different keyvalue "
			  "already exists for %s, keytype %s, kvno %d",
			  name_str, etype_str, entry.vno));
	}
	krb5_kt_free_entry(context, &dummy);
	krb5_kt_free_entry (context, &entry);
	free(name_str);
	free(etype_str);
	return ret;
    } else if(ret != KRB5_KT_NOTFOUND) {
	krb5_set_error_message (context, ret, "fetching %s/%s/%u",
				name_str, etype_str, entry.vno);
	krb5_kt_free_entry (context, &entry);
	free(name_str);
	free(etype_str);
	return ret;
    }
    ret = krb5_kt_add_entry (context, dst_keytab, &entry);
    krb5_kt_free_entry (context, &entry);
    if (ret) {
	krb5_set_error_message (context, ret, "adding %s/%s/%u",
				name_str, etype_str, entry.vno);
	free(name_str);
	free(etype_str);
	return ret;
    }
    free(name_str);
    free(etype_str);
    return ret;
}

krb5_error_code kt_copy(krb5_context context, const char *from, const char *to)
{
    krb5_error_code ret;
    krb5_keytab src_keytab, dst_keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    ret = krb5_kt_resolve (context, from, &src_keytab);
    if (ret) {
	krb5_set_error_message (context, ret, "resolving src keytab `%s'", from);
	return ret;
    }

    ret = krb5_kt_resolve (context, to, &dst_keytab);
    if (ret) {
	krb5_kt_close (context, src_keytab);
	krb5_set_error_message (context, ret, "resolving dst keytab `%s'", to);
	return ret;
    }

    ret = krb5_kt_start_seq_get (context, src_keytab, &cursor);
    if (ret) {
	krb5_set_error_message (context, ret, "krb5_kt_start_seq_get %s", from);
	goto out;
    }

    while((ret = krb5_kt_next_entry(context, src_keytab,
				    &entry, &cursor)) == 0) {
	ret = copy_one_entry(context, src_keytab, dst_keytab, entry);
	if (ret) {
	    break;
	}
    }
    krb5_kt_end_seq_get (context, src_keytab, &cursor);

  out:
    krb5_kt_close (context, src_keytab);
    krb5_kt_close (context, dst_keytab);
    if (ret == KRB5_KT_END) {
	return 0;
    } else if (ret == 0) {
	return EINVAL;
    }
    return ret;
}

krb5_error_code kt_copy_one_principal(krb5_context context,
				      const char *from,
				      const char *to,
				      const char *principal,
				      krb5_kvno kvno,
				      const krb5_enctype *enctypes)
{
    krb5_error_code ret;
    krb5_keytab src_keytab, dst_keytab;
    krb5_keytab_entry entry;
    krb5_principal princ;
    int i;
    bool found_one = false;

    ret = krb5_parse_name (context, principal, &princ);
    if(ret) {
	    krb5_set_error_message(context, ret, "krb5_unparse_name");
	    return ret;
    }

    ret = krb5_kt_resolve (context, from, &src_keytab);
    if (ret) {
	krb5_set_error_message(context, ret, "resolving src keytab `%s'", from);
	return ret;
    }

    ret = krb5_kt_resolve (context, to, &dst_keytab);
    if (ret) {
	krb5_kt_close (context, src_keytab);
	krb5_set_error_message(context, ret, "resolving dst keytab `%s'", to);
	return ret;
    }

    for (i=0; enctypes[i]; i++) {
  	ret = krb5_kt_get_entry(context, src_keytab,
				princ,
				kvno,
				enctypes[i],
				&entry);
	if (ret == KRB5_KT_NOTFOUND) {
	    continue;
	} else if (ret) {
	    break;
	}
	found_one = true;
	ret = copy_one_entry(context, src_keytab, dst_keytab, entry);
	if (ret) {
	    break;
	}
    }
    if (ret == KRB5_KT_NOTFOUND) {
	if (!found_one) {
	    char *princ_string;
	    int ret2 = krb5_unparse_name (context, princ, &princ_string);
	    if (ret2) {
		krb5_set_error_message(context, ret,
					"failed to fetch principal %s",
					princ_string);
	    }
	} else {
	    /* Not finding an enc type is not an error,
	     * as long as we copied one for the principal */
	    ret = 0;
	}
    }

    krb5_kt_close (context, src_keytab);
    krb5_kt_close (context, dst_keytab);
    return ret;
}

#if !defined(HAVE_KRB5_KT_COMPARE)
krb5_boolean smb_krb5_kt_compare(krb5_context context,
				 krb5_keytab_entry *entry,
				 krb5_const_principal principal,
				 krb5_kvno kvno,
				 krb5_enctype enctype)
{
	if (principal) {
		if (!krb5_principal_compare(context,
					    entry->principal, principal)) {
			return false;
		}
	}
	if (kvno) {
		if (entry->vno != kvno) {
			return false;
		}
	}
	if (enctype) {
		if (KRB5_KEY_TYPE(KRB5_KT_KEY(entry)) != enctype) {
			return false;
		}
	}

	return true;
}
#endif

