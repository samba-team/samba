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

/*
  Put an AFS token into the Kernel so that it can authenticate against
  the AFS server. This assumes correct local uid settings.

  This is currently highly Linux and OpenAFS-specific. The correct API
  call for this would be ktc_SetToken. But to do that we would have to
  import a REALLY big bunch of libraries which I would currently like
  to avoid. 
*/

static BOOL afs_settoken(const char *username, const char *cell,
			 const struct ClearToken *ctok,
			 char *v4tkt_data, int v4tkt_length)
{
	int ret;
	struct {
		char *in, *out;
		uint16 in_size, out_size;
	} iob;

	char buf[1024];
	char *p = buf;
	int tmp;

	memcpy(p, &v4tkt_length, sizeof(uint32));
	p += sizeof(uint32);
	memcpy(p, v4tkt_data, v4tkt_length);
	p += v4tkt_length;

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

/*
  This routine takes a radical approach completely defeating the
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
	fstring ticket;
	char *p = ticket;
	uint32 len;
	struct afs_key key;
	pstring afs_username;
	char *cell;

	struct ClearToken ct;

	uint32 now;		/* I assume time() returns 32 bit */

	des_key_schedule key_schedule;

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

	if (!secrets_init()) 
		return False;

	if (!secrets_fetch_afs_key(cell, &key)) {
		DEBUG(5, ("Could not fetch AFS service key\n"));
		return False;
	}

	ct.AuthHandle = key.kvno;

	/* Build the ticket. This is going to be encrypted, so in our
           way we fill in ct while we still have the unencrypted
           form. */

	p = ticket;

	/* The byte-order */
	*p = 1;
	p += 1;

	/* "Alice", the client username */
	strncpy(p, afs_username, sizeof(ticket)-PTR_DIFF(p,ticket)-1);
	p += strlen(p)+1;
	strncpy(p, "", sizeof(ticket)-PTR_DIFF(p,ticket)-1);
	p += strlen(p)+1;
	strncpy(p, cell, sizeof(ticket)-PTR_DIFF(p,ticket)-1);
	p += strlen(p)+1;

	/* This assumes that we have setresuid and set the real uid as well as
	   the effective uid in set_effective_uid(). */
	ct.ViceId = getuid();
	DEBUG(10, ("Creating Token for uid %d\n", ct.ViceId));

	/* Alice's network layer address. At least Openafs-1.2.10
           ignores this, so we fill in a dummy value here. */
	SIVAL(p, 0, 0);
	p += 4;

	/* We need to create a session key */
	generate_random_buffer(p, 8, False);

	/* Our client code needs the the key in the clear, it does not
           know the server-key ... */
	memcpy(ct.HandShakeKey, p, 8);

	p += 8;

	/* Ticket lifetime. We fake everything here, so go as long as
	   possible. This is in 5-minute intervals, so 255 is 21 hours
	   and 15 minutes.*/
	*p = 255;
	p += 1;

	/* Ticket creation time */
	now = time(NULL);
	SIVAL(p, 0, now);
	ct.BeginTimestamp = now;

	ct.EndTimestamp = now + (255*60*5);
	if (((ct.EndTimestamp - ct.BeginTimestamp) & 1) == 1) {
		ct.BeginTimestamp += 1; /* Lifetime must be even */
	}
	p += 4;

	/* And here comes Bob's name and instance, in this case the
           AFS server. */
	strncpy(p, "afs", sizeof(ticket)-PTR_DIFF(p,ticket)-1);
	p += strlen(p)+1;
	strncpy(p, "", sizeof(ticket)-PTR_DIFF(p,ticket)-1);
	p += strlen(p)+1;

	/* And zero-pad to a multiple of 8 bytes */
	len = PTR_DIFF(p, ticket);
	if (len & 7) {
		uint32 extra_space = 8-(len & 7);
		memset(p, 0, extra_space);
		p+=extra_space;
	}
	len = PTR_DIFF(p, ticket);

	des_key_sched((const_des_cblock *)key.key, key_schedule);
	des_pcbc_encrypt(ticket, ticket,
			 len, key_schedule, (C_Block *)key.key, 1);

	ZERO_STRUCT(key);

	return afs_settoken(afs_username, cell, &ct, ticket, len);
}

#else

BOOL afs_login(connection_struct *conn)
{
	return True;
}

#endif /* WITH_FAKE_KASERVER */
