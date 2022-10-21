/*
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
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

#ifndef KADM5_HOOK_H
#define KADM5_HOOK_H 1

#define KADM5_HOOK_VERSION_V1 1

#include <heimbase-svc.h>

/*
 * Each hook is called before the operation using KADM5_STAGE_PRECOMMIT and
 * then after the operation using KADM5_STAGE_POSTCOMMIT. If the hook returns
 * failure during precommit, the operation is aborted without changes to the
 * database. All post-commit hook are invoked if the operation was attempted.
 *
 * Note that unlike libkrb5 plugins, returning success does not prevent other
 * plugins being called (i.e. it is equivalent to KRB5_PLUGIN_NO_HANDLE).
 */
enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT,
    KADM5_HOOK_STAGE_POSTCOMMIT
};

#define KADM5_HOOK_FLAG_KEEPOLD	    0x1 /* keep old password */
#define KADM5_HOOK_FLAG_CONDITIONAL 0x2 /* only change password if different */

typedef struct kadm5_hook_ftable {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);

    const char *name;
    const char *vendor;

    /*
     * Hook functions; NULL functions are ignored. code is only valid on
     * post-commit hooks and represents the result of the commit. Post-
     * commit hooks are not called if a pre-commit hook aborted the call.
     */
    krb5_error_code (KRB5_CALLCONV *chpass)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ,
					    uint32_t flags,
					    size_t n_ks_tuple,
					    krb5_key_salt_tuple *ks_tuple,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *chpass_with_key)(krb5_context context,
						     void *data,
						     enum kadm5_hook_stage stage,
						     krb5_error_code code,
						     krb5_const_principal princ,
						     uint32_t flags,
						     size_t n_key_data,
						     krb5_key_data *key_data);

    krb5_error_code (KRB5_CALLCONV *create)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *modify)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask);

    krb5_error_code (KRB5_CALLCONV *delete)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *randkey)(krb5_context context,
					     void *data,
					     enum kadm5_hook_stage stage,
					     krb5_error_code code,
					     krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *rename)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal source,
					    krb5_const_principal target);

    krb5_error_code (KRB5_CALLCONV *set_keys)(krb5_context context,
					      void *data,
					      enum kadm5_hook_stage stage,
					      krb5_error_code code,
					      krb5_const_principal princ,
					      uint32_t flags,
					      size_t n_ks_tuple,
					      krb5_key_salt_tuple *ks_tuple,
					      size_t n_keys,
					      krb5_keyblock *keyblocks);

    krb5_error_code (KRB5_CALLCONV *prune)(krb5_context context,
					   void *data,
					   enum kadm5_hook_stage stage,
					   krb5_error_code code,
					   krb5_const_principal princ,
					   int kvno);

} kadm5_hook_ftable;

/*
 * libkadm5srv expects a symbol named kadm5_hook_plugin_load that must be a
 * function of type kadm5_hook_plugin_load_t.
 */
typedef krb5_error_code
(KRB5_CALLCONV *kadm5_hook_plugin_load_t)(krb5_context context,
					  krb5_get_instance_func_t *func,
					  size_t *n_hooks,
					  const kadm5_hook_ftable *const **hooks);

#endif /* !KADM5_HOOK_H */
