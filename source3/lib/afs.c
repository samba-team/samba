/* 
 *  Unix SMB/CIFS implementation.
 *  Generate AFS tickets
 *  Copyright (C) Volker Lendecke 2003
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#ifdef WITH_FAKE_KASERVER

#include <afs/stds.h>
#include <afs/afs.h>
#include <afs/auth.h>
#include <afs/venus.h>
#include <asm/unistd.h>
#include <openssl/des.h>

_syscall5(int, afs_syscall, int, subcall,
	  char *, path,
	  int, cmd,
	  char *, cmarg,
	  int, follow);

struct ClearToken {
	uint32 AuthHandle;
	char HandShakeKey[8];
	uint32 ViceId;
	uint32 BeginTimestamp;
	uint32 EndTimestamp;
};

static char *afs_encode_token(const char *cell, const DATA_BLOB ticket,
			      const struct ClearToken *ct)
{
	char *base64_ticket;
	char *result;

	DATA_BLOB key = data_blob(ct->HandShakeKey, 8);
	char *base64_key;

	base64_ticket = base64_encode_data_blob(ticket);
	if (base64_ticket == NULL)
		return NULL;

	base64_key = base64_encode_data_blob(key);
	if (base64_key == NULL) {
		free(base64_ticket);
		return NULL;
	}

	asprintf(&result, "%s\n%u\n%s\n%u\n%u\n%u\n%s\n", cell,
		 ct->AuthHandle, base64_key, ct->ViceId, ct->BeginTimestamp,
		 ct->EndTimestamp, base64_ticket);

	DEBUG(10, ("Got ticket string:\n%s\n", result));

	free(base64_ticket);
	free(base64_key);

	return result;
}

static BOOL afs_decode_token(const char *string, char **cell,
			     DATA_BLOB *ticket, struct ClearToken *ct)
{
	DATA_BLOB blob;
	struct ClearToken result_ct;

	char *s = strdup(string);

	char *t;

	if ((t = strtok(s, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	*cell = strdup(t);

	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	if (sscanf(t, "%u", &result_ct.AuthHandle) != 1) {
		DEBUG(10, ("sscanf AuthHandle failed\n"));
		return False;
	}
		
	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	blob = base64_decode_data_blob(t);

	if ( (blob.data == NULL) ||
	     (blob.length != sizeof(result_ct.HandShakeKey) )) {
		DEBUG(10, ("invalid key: %x/%d\n", (uint32)blob.data,
			   blob.length));
		return False;
	}

	memcpy(result_ct.HandShakeKey, blob.data, blob.length);

	data_blob_free(&blob);

	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	if (sscanf(t, "%u", &result_ct.ViceId) != 1) {
		DEBUG(10, ("sscanf ViceId failed\n"));
		return False;
	}
		
	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	if (sscanf(t, "%u", &result_ct.BeginTimestamp) != 1) {
		DEBUG(10, ("sscanf BeginTimestamp failed\n"));
		return False;
	}
		
	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	if (sscanf(t, "%u", &result_ct.EndTimestamp) != 1) {
		DEBUG(10, ("sscanf EndTimestamp failed\n"));
		return False;
	}
		
	if ((t = strtok(NULL, "\n")) == NULL) {
		DEBUG(10, ("strtok failed\n"));
		return False;
	}

	blob = base64_decode_data_blob(t);

	if (blob.data == NULL) {
		DEBUG(10, ("Could not get ticket\n"));
		return False;
	}

	*ticket = blob;
	*ct = result_ct;

	return True;
}

/*
  Put an AFS token into the Kernel so that it can authenticate against
  the AFS server. This assumes correct local uid settings.

  This is currently highly Linux and OpenAFS-specific. The correct API
  call for this would be ktc_SetToken. But to do that we would have to
  import a REALLY big bunch of libraries which I would currently like
  to avoid. 
*/

static BOOL afs_settoken(const char *cell,
			 const struct ClearToken *ctok,
			 DATA_BLOB ticket)
{
	int ret;
	struct {
		char *in, *out;
		uint16 in_size, out_size;
	} iob;

	char buf[1024];
	char *p = buf;
	int tmp;

	memcpy(p, &ticket.length, sizeof(uint32));
	p += sizeof(uint32);
	memcpy(p, ticket.data, ticket.length);
	p += ticket.length;

	tmp = sizeof(struct ClearToken);
	memcpy(p, &tmp, sizeof(uint32));
	p += sizeof(uint32);
	memcpy(p, ctok, tmp);
	p += tmp;

	tmp = 0;

	memcpy(p, &tmp, sizeof(uint32));
	p += sizeof(uint32);

	tmp = strlen(cell);
	if (tmp >= MAXKTCREALMLEN) {
		DEBUG(1, ("Realm too long\n"));
		return False;
	}

	strncpy(p, cell, tmp);
	p += tmp;
	*p = 0;
	p +=1;

	iob.in = buf;
	iob.in_size = PTR_DIFF(p,buf);
	iob.out = buf;
	iob.out_size = sizeof(buf);

#if 0
	file_save("/tmp/ioctlbuf", iob.in, iob.in_size);
#endif

	ret = afs_syscall(AFSCALL_PIOCTL, 0, VIOCSETTOK, (char *)&iob, 0);

	DEBUG(10, ("afs VIOCSETTOK returned %d\n", ret));
	return (ret == 0);
}

BOOL afs_settoken_str(const char *token_string)
{
	DATA_BLOB ticket;
	struct ClearToken ct;
	BOOL result;
	char *cell;

	if (!afs_decode_token(token_string, &cell, &ticket, &ct))
		return False;

	if (geteuid() != 0)
		ct.ViceId = getuid();

	result = afs_settoken(cell, &ct, ticket);

	SAFE_FREE(cell);
	data_blob_free(&ticket);

	return result;
	}

/* Create a ClearToken and an encrypted ticket. ClearToken has not yet the
 * ViceId set, this should be set by the caller. */

static BOOL afs_createtoken(const char *username, const char *cell,
			    DATA_BLOB *ticket, struct ClearToken *ct)
{
	fstring clear_ticket;
	char *p = clear_ticket;
	uint32 len;
	uint32 now;

	struct afs_key key;
	des_key_schedule key_schedule;

	if (!secrets_init()) 
		return False;

	if (!secrets_fetch_afs_key(cell, &key)) {
		DEBUG(1, ("Could not fetch AFS service key\n"));
		return False;
	}

	ct->AuthHandle = key.kvno;

	/* Build the ticket. This is going to be encrypted, so in our
           way we fill in ct while we still have the unencrypted
           form. */

	p = clear_ticket;

	/* The byte-order */
	*p = 1;
	p += 1;

	/* "Alice", the client username */
	strncpy(p, username, sizeof(clear_ticket)-PTR_DIFF(p,clear_ticket)-1);
	p += strlen(p)+1;
	strncpy(p, "", sizeof(clear_ticket)-PTR_DIFF(p,clear_ticket)-1);
	p += strlen(p)+1;
	strncpy(p, cell, sizeof(clear_ticket)-PTR_DIFF(p,clear_ticket)-1);
	p += strlen(p)+1;

	/* Alice's network layer address. At least Openafs-1.2.10
           ignores this, so we fill in a dummy value here. */
	SIVAL(p, 0, 0);
	p += 4;

	/* We need to create a session key */
	generate_random_buffer(p, 8, False);

	/* Our client code needs the the key in the clear, it does not
           know the server-key ... */
	memcpy(ct->HandShakeKey, p, 8);

	p += 8;

	/* Ticket lifetime. We fake everything here, so go as long as
	   possible. This is in 5-minute intervals, so 255 is 21 hours
	   and 15 minutes.*/
	*p = 255;
	p += 1;

	/* Ticket creation time */
	now = time(NULL);
	SIVAL(p, 0, now);
	ct->BeginTimestamp = now;

	ct->EndTimestamp = now + (255*60*5);
	if (((ct->EndTimestamp - ct->BeginTimestamp) & 1) == 1) {
		ct->BeginTimestamp += 1; /* Lifetime must be even */
	}
	p += 4;

	/* And here comes Bob's name and instance, in this case the
           AFS server. */
	strncpy(p, "afs", sizeof(clear_ticket)-PTR_DIFF(p,clear_ticket)-1);
	p += strlen(p)+1;
	strncpy(p, "", sizeof(clear_ticket)-PTR_DIFF(p,clear_ticket)-1);
	p += strlen(p)+1;

	/* And zero-pad to a multiple of 8 bytes */
	len = PTR_DIFF(p, clear_ticket);
	if (len & 7) {
		uint32 extra_space = 8-(len & 7);
		memset(p, 0, extra_space);
		p+=extra_space;
	}
	len = PTR_DIFF(p, clear_ticket);

	des_key_sched((const_des_cblock *)key.key, key_schedule);
	des_pcbc_encrypt(clear_ticket, clear_ticket,
			 len, key_schedule, (C_Block *)key.key, 1);

	ZERO_STRUCT(key);

	*ticket = data_blob(clear_ticket, len);

	return True;
}

char *afs_createtoken_str(const char *username, const char *cell)
{
	DATA_BLOB ticket;
	struct ClearToken ct;
	char *result;

	if (!afs_createtoken(username, cell, &ticket, &ct))
		return NULL;

	result = afs_encode_token(cell, ticket, &ct);

	data_blob_free(&ticket);

	return result;
}

/*
  This routine takes a radical approach completely bypassing the
  Kerberos idea of security and using AFS simply as an intelligent
  file backend. Samba has persuaded itself somehow that the user is
  actually correctly identified and then we create a ticket that the
  AFS server hopefully accepts using its KeyFile that the admin has
  kindly stored to our secrets.tdb.

  Thanks to the book "Network Security -- PRIVATE Communication in a
  PUBLIC World" by Charlie Kaufman, Radia Perlman and Mike Speciner
  Kerberos 4 tickets are not really hard to construct.

  For the comments "Alice" is the User to be auth'ed, and "Bob" is the
  AFS server.  */

BOOL afs_login(connection_struct *conn)
{
	DATA_BLOB ticket;
	pstring afs_username;
	char *cell;
	BOOL result;

	struct ClearToken ct;

	pstrcpy(afs_username, lp_afs_username_map());
	standard_sub_conn(conn, afs_username, sizeof(afs_username));

	/* The pts command always generates completely lower-case user
	 * names. */
	strlower_m(afs_username);

	cell = strchr(afs_username, '@');

	if (cell == NULL) {
		DEBUG(1, ("AFS username doesn't contain a @, "
			  "could not find cell\n"));
		return False;
	}

	*cell = '\0';
	cell += 1;

	DEBUG(10, ("Trying to log into AFS for user %s@%s\n", 
		   afs_username, cell));

	if (!afs_createtoken(afs_username, cell, &ticket, &ct))
		return False;

	/* For which Unix-UID do we want to set the token? */
	ct.ViceId = getuid();

	{
		char *str, *new_cell;
		DATA_BLOB test_ticket;
		struct ClearToken test_ct;

		hex_encode(ct.HandShakeKey, sizeof(ct.HandShakeKey), &str);
		DEBUG(10, ("Key: %s\n", str));
		free(str);

		str = afs_encode_token(cell, ticket, &ct);

		if (!afs_decode_token(str, &new_cell, &test_ticket,
				      &test_ct)) {
			DEBUG(0, ("Could not decode token"));
			goto decode_failed;
		}

		if (strcmp(cell, new_cell) != 0) {
			DEBUG(0, ("cell changed\n"));
		}

		if ((ticket.length != test_ticket.length) ||
		    (memcmp(ticket.data, test_ticket.data,
			    ticket.length) != 0)) {
			DEBUG(0, ("Ticket changed\n"));
		}

		if (memcmp(&ct, &test_ct, sizeof(ct)) != 0) {
			DEBUG(0, ("ClearToken changed\n"));
		}

		data_blob_free(&test_ticket);

	decode_failed:
		SAFE_FREE(str);
		SAFE_FREE(new_cell);
	}

	result = afs_settoken(cell, &ct, ticket);

	data_blob_free(&ticket);

	return result;
}

#else

BOOL afs_login(connection_struct *conn)
{
	return True;
}

BOOL afs_settoken_str(const char *token_string)
{
	return False;
}

char *afs_createtoken_str(const char *username, const char *cell)
{
	return False;
}

#endif /* WITH_FAKE_KASERVER */
