/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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
RCSID("$Id: env.c 19878 2007-01-13 00:58:39Z lha $");

struct hx509_env {
    struct {
	char *key;
	char *value;
    } *val;
    size_t len;
};

int
hx509_env_init(hx509_context context, hx509_env *env)
{
    *env = calloc(1, sizeof(**env));
    if (*env == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    return 0;
}

int
hx509_env_add(hx509_context context, hx509_env env, 
	      const char *key, const char *value)
{
    void *ptr;

    ptr = realloc(env->val, sizeof(env->val[0]) * (env->len + 1));
    if (ptr == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    env->val = ptr;
    env->val[env->len].key = strdup(key);
    if (env->val[env->len].key == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    env->val[env->len].value = strdup(value);
    if (env->val[env->len].value == NULL) {
	free(env->val[env->len].key);
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }
    env->len++;
    return 0;
}

const char *
hx509_env_lfind(hx509_context context, hx509_env env,
		const char *key, size_t len)
{
    size_t i;

    for (i = 0; i < env->len; i++) {
	char *s = env->val[i].key;
	if (strncmp(key, s, len) == 0 && s[len] == '\0')
	    return env->val[i].value;
    }
    return NULL;
}


void
hx509_env_free(hx509_env *env)
{
    size_t i;

    for (i = 0; i < (*env)->len; i++) {
	free((*env)->val[i].key);
	free((*env)->val[i].value);
    }
    free((*env)->val);
    free(*env);
    *env = NULL;
}

