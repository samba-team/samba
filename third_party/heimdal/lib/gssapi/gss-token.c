/* */

/*-
 * Copyright (c) 1997-2011 Roland C. Dowdeswell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer and
 *    dedication in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <errno.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include <base64.h>
#include <getarg.h>
#include <roken.h>
#include <vers.h>

#define GBAIL(x, _maj, _min)	do {					\
		if (GSS_ERROR(_maj)) {					\
			char	*the_gss_err;				\
									\
			ret = 1;					\
			the_gss_err = gss_mk_err(_maj, _min, x);	\
			if (the_gss_err)				\
				fprintf(stderr, "%s\n", the_gss_err);	\
			else						\
				fprintf(stderr, "err making err\n");	\
			free(the_gss_err);				\
			goto bail;					\
		}							\
	} while (0)

#define K5BAIL(x)	do {						\
		kret = x;						\
		if (kret) {						\
			const char 	*k5err;				\
									\
			k5err = krb5_get_error_message(kctx, kret);	\
			if (k5err) {					\
				fprintf(stderr, "%s in %s:%s\n", k5err,	\
				    #x, __func__);			\
				krb5_free_error_message(kctx, k5err);	\
			} else {					\
				fprintf(stderr, "unknown error %d in "	\
				    "%s:%s\n", kret, #x, __func__);	\
			}						\
			exit(1); /* XXXrcd: shouldn't exit */		\
		}							\
	} while (0)


/*
 * global variables
 */

int	Sflag = 0;
int	nflag = 0;
gss_OID	global_mech = GSS_C_NO_OID;

static char *
gss_mk_err(OM_uint32 maj_stat, OM_uint32 min_stat, const char *preamble)
{
	gss_buffer_desc	 status;
	OM_uint32	 new_stat;
	OM_uint32	 cur_stat;
	OM_uint32	 msg_ctx = 0;
	OM_uint32	 ret;
	int		 type;
	size_t		 newlen;
	char		*str = NULL;
	char		*tmp = NULL;

	cur_stat = maj_stat;
	type = GSS_C_GSS_CODE;

	for (;;) {

		/*
		 * GSS_S_FAILURE produces a rather unhelpful message, so
		 * we skip straight to the mech specific error in this case.
		 */

		if (type == GSS_C_GSS_CODE && cur_stat == GSS_S_FAILURE) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
		}

		ret = gss_display_status(&new_stat, cur_stat, type,
		    GSS_C_NO_OID, &msg_ctx, &status);

		if (GSS_ERROR(ret))
			return str;	/* XXXrcd: hmmm, not quite?? */

		if (str)
			newlen = strlen(str);
		else
			newlen = strlen(preamble);

		newlen += status.length + 3;

		tmp = str;
		str = malloc(newlen);

		if (!str) {
			gss_release_buffer(&new_stat, &status);
			return tmp;	/* XXXrcd: hmmm, not quite?? */
		}

		snprintf(str, newlen, "%s%s%.*s", tmp?tmp:preamble,
		    tmp?", ":": ", (int)status.length, (char *)status.value);

		gss_release_buffer(&new_stat, &status);
		free(tmp);

		/*
		 * If we are finished processing for maj_stat, then
		 * move onto min_stat.
		 */

		if (msg_ctx == 0 && type == GSS_C_GSS_CODE && min_stat != 0) {
			type = GSS_C_MECH_CODE;
			cur_stat = min_stat;
			continue;
		}

		if (msg_ctx == 0)
			break;
	}

	return str;
}

static char *
read_buffer(FILE *fp)
{
	char	 buf[65536];
	char	*p;
	char	*ret = NULL;
	size_t	 buflen;
	size_t	 retlen = 0;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((p = strchr(buf, '\n')) == NULL) {
			fprintf(stderr, "Long line, exiting.\n");
			exit(1);
		}
		*p = '\0';
		buflen = strlen(buf);
		if (buflen == 0)
			break;

		ret = realloc(ret, retlen + buflen + 1);
		if (!ret) {
			perror("realloc");
			exit(1);
		}
		memcpy(ret + retlen, buf, buflen);
		ret[retlen + buflen] = '\0';
		retlen += buflen;
	}

	if (ferror(stdin)) {
		perror("fgets");
		exit(1);
	}

	return ret;
}

static int
write_and_free_token(gss_buffer_t out, int negotiate)
{
	OM_uint32	 min;
	char		*outstr = NULL;
	char		*p = out->value;
	size_t		 len = out->length;
	size_t		 inc;
	int		 ret = 0;
	int		 first = 1;

	if (nflag)
		goto bail;

	/*
	 * According to RFC 2744 page 25, we simply don't output
	 * zero length output tokens.
	 */
	if (len == 0)
		goto bail;

	inc = len;
	if (Sflag)
		inc = Sflag;

	do {
		if (first)
			first = 0;
		else
			printf("\n");
		if (len < inc)
			inc = len;
		if (rk_base64_encode(p, inc, &outstr) < 0) {
			fprintf(stderr, "Out of memory.\n");
			ret = errno;
			goto bail;
		}
                ret = 0;
		printf("%s%s\n", negotiate?"Negotiate ":"", outstr);
		free(outstr);
		p   += inc;
		len -= inc;
	} while (len > 0);
        ret = 0;

bail:
	gss_release_buffer(&min, out);
	return ret;
}

static int
read_token(gss_buffer_t in, int negotiate)
{
	char	*inbuf = NULL;
	char	*tmp;
	size_t	 len;
	int	 ret = 0;

	/* We must flush before we block wanting input */
	fflush(stdout);

	*in = (gss_buffer_desc)GSS_C_EMPTY_BUFFER;
	inbuf = read_buffer(stdin);
	if (!inbuf)
		/* Just a couple of \n's in a row or EOF, no error. */
		return 0;

	tmp = inbuf;
	if (negotiate) {
		if (strncasecmp("Negotiate ", inbuf, 10) != 0) {
			fprintf(stderr, "Token doesn't begin with "
			    "\"Negotiate \"\n");
			ret = -1;
			goto bail;
		}

		tmp += 10;
	}

	len = strlen(tmp);
	in->value = malloc(len + 1);
	if (!in->value) {
		fprintf(stderr, "Out of memory.\n");
		ret = -1;
		goto bail;
	}
	ret = rk_base64_decode(tmp, in->value);
	if (ret < 0) {
		free(in->value);
		in->value = NULL;
		if (errno == EOVERFLOW)
			fprintf(stderr, "Token is too big\n");
		else
			fprintf(stderr, "Token encoding is not valid "
			    "base64\n");
		goto bail;
	} else {
		in->length = ret;
	}
	ret = 0;

bail:
	free(inbuf);
	return ret;
}

static int
initiate_one(gss_name_t service, int delegate, int negotiate)
{
	gss_ctx_id_t	 ctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc	 in;
	gss_buffer_desc	 out;
	OM_uint32	 maj;
	OM_uint32	 min;
	OM_uint32	 flags = 0;
	int		 first = 1;
	int		 ret = 0;

	if (delegate)
		flags |= GSS_C_DELEG_FLAG;

	do {
		out.length = 0;
		out.value  = 0;

		if (first) {
			in.length  = 0;
			in.value   = 0;
			first      = 0;
		} else {
			printf("\n");
			ret = read_token(&in, negotiate);
			if (ret)
				return ret;
			if (feof(stdin))
				return -1;
		}

		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
		    service, global_mech, flags, 0,
		    GSS_C_NO_CHANNEL_BINDINGS, &in, NULL, &out,
		    NULL, NULL);

		ret = write_and_free_token(&out, negotiate);
		if (ret)
			return ret;

		GBAIL("gss_init_sec_context", maj, min);
	} while (maj & GSS_S_CONTINUE_NEEDED);

bail:
	if (ctx != GSS_C_NO_CONTEXT) {
		/*
		 * XXXrcd: here we ignore the fact that we might have an
		 *         output token as this program doesn't do terribly
		 *         well in that case.
		 */
		gss_delete_sec_context(&min, &ctx, NULL);
	}

	return ret;
}

static krb5_error_code
copy_cache(krb5_context kctx, krb5_ccache from, krb5_ccache to)
{
	krb5_error_code	kret;
	krb5_principal	princ = NULL;
	krb5_cc_cursor	cursor;
	krb5_creds	cred;

	K5BAIL(krb5_cc_get_principal(kctx, from, &princ));
	K5BAIL(krb5_cc_initialize(kctx, to, princ));
	K5BAIL(krb5_cc_start_seq_get(kctx, from, &cursor));
	for (;;) {
		kret = krb5_cc_next_cred(kctx, from, &cursor, &cred);
		if (kret)
			break;
		kret = krb5_cc_store_cred(kctx, to, &cred);
		krb5_free_cred_contents(kctx, &cred);
		if (kret)
			break;
	}
	krb5_cc_end_seq_get(kctx, from, &cursor);

	if (kret == KRB5_CC_END)
		kret = 0;
	K5BAIL(kret);

	if (princ)
		krb5_free_principal(kctx, princ);

	return kret;
}

static int
initiate_many(gss_name_t service, int delegate, int negotiate, int memcache,
	      size_t count)
{
	krb5_error_code	kret = 0;
	krb5_context	kctx = NULL;
	krb5_ccache	def_cache = NULL;
	krb5_ccache	mem_cache = NULL;
	size_t		i;

	if (memcache) {
		K5BAIL(krb5_init_context(&kctx));
		K5BAIL(krb5_cc_default(kctx, &def_cache));
		K5BAIL(krb5_cc_resolve(kctx, "MEMORY:mem_cache", &mem_cache));
		putenv("KRB5CCNAME=MEMORY:mem_cache");
	}

	for (i=0; i < count; i++) {
		if (memcache)
			K5BAIL(copy_cache(kctx, def_cache, mem_cache));
		kret = initiate_one(service, delegate, negotiate);

		if (!nflag && i < count - 1)
			printf("\n");
	}

	if (kctx)
		krb5_free_context(kctx);
	if (def_cache)
		krb5_cc_close(kctx, def_cache);
	if (mem_cache)
		krb5_cc_close(kctx, mem_cache);

	return kret;
}

static int
accept_one(gss_name_t service, const char *ccname, int negotiate)
{
	gss_cred_id_t	 cred = NULL;
	gss_cred_id_t	 deleg_creds = NULL;
        gss_name_t       client;
        gss_OID          mech_oid;
        gss_ctx_id_t     ctx = GSS_C_NO_CONTEXT;
        gss_buffer_desc  in = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc  out;
        gss_buffer_desc  dname = GSS_C_EMPTY_BUFFER;
	krb5_context	 kctx = NULL;
	krb5_ccache	 ccache = NULL;
	krb5_error_code	 kret;
        OM_uint32        maj, min;
	int		 ret = 0;

	if (service) {
		maj = gss_acquire_cred(&min, service, 0, NULL, GSS_C_ACCEPT,
		    &cred, NULL, NULL);
		GBAIL("gss_acquire_cred", maj, min);
	}

	do {
		if (feof(stdin))
			return -1;
		ret = read_token(&in, negotiate);
		if (ret)
			return ret;

		out.length = 0;
		out.value  = 0;

		maj = gss_accept_sec_context(&min, &ctx, cred, &in,
		    GSS_C_NO_CHANNEL_BINDINGS, &client, &mech_oid, &out,
		    NULL, NULL, &deleg_creds);

		ret = write_and_free_token(&out, negotiate);
		if (ret) {
			OM_uint32 junk;

			(void) gss_delete_sec_context(&junk, &ctx,
						      GSS_C_NO_BUFFER);
			return ret;
		}
		GBAIL("gss_accept_sec_context", maj, min);
	} while (maj & GSS_S_CONTINUE_NEEDED);

	/*
	 * XXXrcd: not bothering to clean up because we're about to exit.
	 *         Probably should fix this in case the code is used as
	 *         an example by someone.
	 */

	maj = gss_display_name(&min, client, &dname, NULL);
	GBAIL("gss_display_name", maj, min);

	if (!nflag)
		printf("Authenticated: %.*s\n", (int)dname.length,
		    (char *)dname.value);
	(void) gss_release_buffer(&min, &dname);
	(void) gss_release_name(&min, &client);
	(void) gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);

	if (ccname) {
#ifdef HAVE_GSS_STORE_CRED_INTO
		gss_key_value_set_desc		store;
		gss_key_value_element_desc	elem;
		int				overwrite_cred = 1;
		int				default_cred = 0;

		elem.key = "ccache";
		elem.value = ccname;
		store.count = 1;
		store.elements = &elem;

		maj = gss_store_cred_into(&min, deleg_creds, GSS_C_INITIATE,
		    GSS_C_NO_OID, overwrite_cred, default_cred, &store, NULL,
		    NULL);
		GBAIL("gss_store_cred_into", maj, min);
#else
		K5BAIL(krb5_init_context(&kctx));
		K5BAIL(krb5_cc_resolve(kctx, ccname, &ccache));

		maj = gss_krb5_copy_ccache(&min, deleg_creds, ccache);
		GBAIL("gss_krb5_copy_ccache", maj, min);
#endif
	}

bail:
	if (kctx)
		krb5_free_context(kctx);
	if (ccache)
		krb5_cc_close(kctx, ccache);
	if (cred)
		gss_release_cred(&min, &cred);
	if (deleg_creds)
		gss_release_cred(&min, &deleg_creds);

	free(in.value);

	return ret;
}

static gss_name_t
import_service(char *service)
{
	gss_buffer_desc	name;
	gss_name_t	svc = NULL;
	OM_uint32	maj;
	OM_uint32	min;
	int		ret = 0;

	name.length = strlen(service);
	name.value  = service;

	maj = gss_import_name(&min, &name, GSS_C_NT_HOSTBASED_SERVICE, &svc);

	GBAIL("gss_import_name", maj, min);

bail:
	if (ret)
		exit(1);
	return svc;
}

static void
print_all_mechs(void)
{
	OM_uint32	maj, min;
	gss_OID_set	mech_set;
	size_t		i;
	int		ret = 0;

	maj = gss_indicate_mechs(&min, &mech_set);
	GBAIL("gss_indicate_mechs", maj, min);

	for (i=0; i < mech_set->count; i++)
		printf("%s\n", gss_oid_to_name(&mech_set->elements[i]));

	(void) gss_release_oid_set(&min, &mech_set);

bail:
	exit(ret);
}

static void
usage(int ecode)
{
	FILE *f = ecode == 0 ? stdout : stderr;
	fprintf(f, "Usage: gss-token [-DNn] [-c count] service@host\n");
	fprintf(f, "       gss-token -r [-Nln] [-C ccache] [-c count] "
	    "[service@host]\n");
	exit(ecode);
}

int
main(int argc, char **argv)
{
	OM_uint32	 min;
	gss_name_t	 service = NULL;
	size_t		 count = 1;
	int		 Dflag = 0;
	int		 Mflag = 0;
	int		 Nflag = 0;
	int		 hflag = 0;
	int		 lflag = 0;
	int		 rflag = 0;
	int		 version_flag = 0;
	int		 ret = 0;
	int		 optidx = 0;
	char		*ccname = NULL;
	char		*mech = NULL;
	struct getargs	 args[] = {
	    { "help", 'h', arg_flag, &hflag, NULL, NULL },
	    { "version", 0, arg_flag, &version_flag, NULL, NULL },
	    { NULL, 'C', arg_string, &ccname, NULL, NULL },
	    { NULL, 'D', arg_flag, &Dflag, NULL, NULL },
	    { NULL, 'M', arg_flag, &Mflag, NULL, NULL },
	    { NULL, 'N', arg_flag, &Nflag, NULL, NULL },
	    { NULL, 'S', arg_integer, &Sflag, NULL, NULL },
	    { NULL, 'c', arg_integer, &count, NULL, NULL },
	    { NULL, 'l', arg_flag, &lflag, NULL, NULL },
	    { NULL, 'm', arg_string, &mech, NULL, NULL },
	    { NULL, 'n', arg_flag, &nflag, NULL, NULL },
	    { NULL, 'r', arg_flag, &rflag, NULL, NULL },
	};

	setprogname(argv[0]);
	if (argc == 1 || 
	    getarg(args, sizeof(args)/sizeof(args[0]), argc, argv, &optidx))
	    usage(1);
	if (hflag)
	    usage(0);
	if (version_flag) {
	    print_version(NULL);
	    return 0;
	}

	argc -= optidx;
	argv += optidx;

	if (mech) {
		if (mech[0] == '?' && mech[1] == '\0') {
			print_all_mechs();
			exit(0);
		}
		global_mech = gss_name_to_oid(mech);
		if (!global_mech) {
			fprintf(stderr, "Invalid mech \"%s\".\n", mech);
			usage(1);
		}
	}

	if (argc > 0)
		service = import_service(*argv);

	if (!rflag) {
		if (!argc) {
			fprintf(stderr, "Without -r, hostbased_service must "
			    "be provided.\n");
			usage(1);
		}
		if (ccname) {
			fprintf(stderr, "Specifying a target ccache doesn't "
			    "make sense without -r.\n");
			usage(1);
		}
		ret = initiate_many(service, Dflag, Nflag, Mflag, count);
		goto done;
	}

	if (Dflag) {
		fprintf(stderr, "Delegating credentials (-D) doesn't make "
		    "sense when reading tokens (-r).\n");
		usage(1);
	}

	do {
		ret = accept_one(service, ccname, Nflag);
	} while (lflag && !ret && !feof(stdin));

done:
	if (service)
		gss_release_name(&min, &service);

	return ret;
}
