/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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

/* $Id$ */

#ifndef __STORE_H__
#define __STORE_H__

krb5_storage *krb5_storage_from_fd(int fd);

krb5_storage *krb5_storage_from_mem(void *buf, size_t len);

krb5_storage *krb5_storage_emem(void);

krb5_error_code krb5_storage_free(krb5_storage *sp);

krb5_error_code krb5_storage_to_data(krb5_storage *sp, krb5_data *data);


#define __PT(N, T) krb5_error_code krb5_store_##N(krb5_storage*, T); krb5_error_code krb5_ret_##N(krb5_storage *, T*)

__PT(int32, int32_t);
__PT(int16, int16_t);
__PT(int8, int8_t);
__PT(data, krb5_data);
__PT(principal, krb5_principal);
__PT(keyblock, krb5_keyblock);
__PT(times, krb5_times);
__PT(address, krb5_address);
__PT(addrs, krb5_addresses);
__PT(authdata, krb5_data);

#undef __PT

krb5_error_code
krb5_store_string(krb5_storage *sp, char *s);

krb5_error_code
krb5_ret_string(krb5_storage *sp, char **string);

krb5_error_code
krb5_store_stringz(krb5_storage *sp, char *s);

krb5_error_code
krb5_ret_stringz(krb5_storage *sp, char **string);

/* mem */

size_t mem_store(krb5_storage *sp, void *data, size_t size);
off_t  mem_seek(krb5_storage *sp, off_t offset, int whence);


#endif /* __STORE_H__ */
