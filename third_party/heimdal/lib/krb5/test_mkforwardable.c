/*
 * Copyright (c) 1997-2021 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Copyright (c) 2021 Isaac Boukris
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

#include "krb5_locl.h"

/*
 * Usage: mkforwardable server out_ccache
 *
 * The default cache contains a ticket to server and the default keytab
 * contains a key to decrypt it, the ticket is decrypted and the forwardable
 * flag is added, the ticket is then re-encrypted and stored in out_cache.
 *
 */

static krb5_context context;

static void
check(krb5_error_code code)
{
    const char *errmsg;

    if (code == 0)
	return;

    errmsg = krb5_get_error_message(context, code);
    fprintf(stderr, "%s\n", errmsg);
    krb5_free_error_message(context, errmsg);

    abort();
}

static void
decrypt_ticket_enc_part(EncryptionKey *key,
			krb5_enctype etype,
			Ticket *ticket,
			EncTicketPart *et)
{
    krb5_error_code ret;
    krb5_data plain;
    size_t len;
    krb5_crypto crypto;

    check(krb5_crypto_init(context, key, etype, &crypto));

    ret = krb5_decrypt_EncryptedData (context,
				      crypto,
				      KRB5_KU_TICKET,
				      &ticket->enc_part,
				      &plain);
    check(ret);

    check(decode_EncTicketPart(plain.data, plain.length, et, &len));

    krb5_data_free (&plain);
    krb5_crypto_destroy(context, crypto);
}

static void
encrypt_ticket_enc_part(EncryptionKey *key,
			krb5_enctype etype,
			krb5_kvno skvno,
			EncTicketPart *et,
			Ticket *ticket)
{
    size_t len, size;
    char *buf;
    krb5_error_code ret;
    krb5_crypto crypto;

    ASN1_MALLOC_ENCODE(EncTicketPart, buf, len, et, &size, ret);
    check(ret);

    check(krb5_crypto_init(context, key, etype, &crypto));
    ret = krb5_encrypt_EncryptedData(context,
				      crypto,
				      KRB5_KU_TICKET,
				      buf,
				      len,
				      skvno,
				      &ticket->enc_part);
    check(ret);

    free(buf);
    krb5_crypto_destroy(context, crypto);
}


int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_keytab kt;
    krb5_keytab_entry entry;
    krb5_enctype etype;
    krb5_creds mc, cred;
    krb5_ccache ccache;
    EncTicketPart et;
    Ticket ticket;
    size_t size;
    krb5_kvno kvno = 0;

    memset(&cred, 0, sizeof(cred));

    if (argc != 3)
	errx(1, "Usage: mkforwardable server out_ccache");

    ret = krb5_init_context(&context);
    if (ret)
	errx(1, "krb5_init_context failed: %u", ret);

    check(krb5_cc_default(context, &ccache));

    krb5_cc_clear_mcred(&mc);

    check(krb5_parse_name(context, argv[1], &mc.server));

    check(krb5_cc_retrieve_cred(context, ccache, 0, &mc, &cred));

    check(decode_Ticket(cred.ticket.data, cred.ticket.length, &ticket, NULL));

    etype = ticket.enc_part.etype;

    if (ticket.enc_part.kvno != NULL)
	kvno = *ticket.enc_part.kvno;

    check(krb5_kt_default(context, &kt));

    check(krb5_kt_get_entry(context, kt, mc.server, kvno, etype, &entry));

    decrypt_ticket_enc_part(&entry.keyblock, etype, &ticket, &et);

    et.flags.forwardable = 1;
    cred.flags.b = et.flags;

    free_EncryptedData(&ticket.enc_part);

    encrypt_ticket_enc_part(&entry.keyblock, etype, kvno, &et, &ticket);

    krb5_data_free(&cred.ticket);
    ASN1_MALLOC_ENCODE(Ticket, cred.ticket.data, cred.ticket.length, &ticket,
		       &size, ret);
    check(ret);

    krb5_cc_close(context, ccache);

    check(krb5_cc_resolve(context, argv[2], &ccache));
    check(krb5_cc_initialize(context, ccache, cred.client));

    check(krb5_cc_store_cred(context, ccache, &cred));

    free_Ticket(&ticket);
    free_EncTicketPart(&et);
    krb5_cc_close(context, ccache);
    krb5_free_principal(context, mc.server);
    krb5_free_cred_contents(context, &cred);
    krb5_kt_free_entry(context, &entry);
    krb5_kt_close(context, kt);

    return 0;
}
