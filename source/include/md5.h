/* 
   Unix SMB/Netbios implementation.
   Version 2.0.

   This code comes directly from the ssh-1.2.27 sources.
   
*/

#ifndef MD5_H
#define MD5_H

struct MD5Context
{
	uint32 buf[4];
	uint32 bits[2];
	uchar in[64];
};

#endif /* !MD5_H */
