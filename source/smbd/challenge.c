/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

extern int DEBUGLEVEL;

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent=False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/
void generate_next_challenge(char *challenge)
{
        unsigned char buf[8];
        generate_random_buffer(buf,8,False);
	memcpy(saved_challenge, buf, 8);
	memcpy(challenge,buf,8);
	challenge_sent = True;
}

/*******************************************************************
set the last challenge sent, usually from a password server
********************************************************************/
BOOL set_challenge(unsigned char *challenge)
{
  memcpy(saved_challenge,challenge,8);
  challenge_sent = True;
  return(True);
}

/*******************************************************************
get the last challenge sent
********************************************************************/
BOOL last_challenge(unsigned char *challenge)
{
  if (!challenge_sent) return False;
  memcpy(challenge,saved_challenge,8);
  return(True);
}

