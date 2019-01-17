/* 
   Unix SMB/CIFS implementation.
   SMB Byte handling
   Copyright (C) Andrew Tridgell 1992-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _BYTEORDER_H
#define _BYTEORDER_H

/*
   This file implements macros for machine independent short and 
   int manipulation

Here is a description of this file that I emailed to the samba list once:

> I am confused about the way that byteorder.h works in Samba. I have
> looked at it, and I would have thought that you might make a distinction
> between LE and BE machines, but you only seem to distinguish between 386
> and all other architectures.
> 
> Can you give me a clue?

sure.

Ok, now to the macros themselves. I'll take a simple example, say we
want to extract a 2 byte integer from a SMB packet and put it into a
type called uint16_t that is in the local machines byte order, and you
want to do it with only the assumption that uint16_t is _at_least_ 16
bits long (this last condition is very important for architectures
that don't have any int types that are 2 bytes long)

You do this:

#define CVAL(buf,pos) (((uint8_t *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned int)CVAL(buf,pos))
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)

then to extract a uint16_t value at offset 25 in a buffer you do this:

char *buffer = foo_bar();
uint16_t xx = SVAL(buffer,25);

We are using the byteoder independence of the ANSI C bitshifts to do
the work. A good optimising compiler should turn this into efficient
code, especially if it happens to have the right byteorder :-)

I know these macros can be made a bit tidier by removing some of the
casts, but you need to look at byteorder.h as a whole to see the
reasoning behind them. byteorder.h defines the following macros:

SVAL(buf,pos) - extract a 2 byte SMB value
IVAL(buf,pos) - extract a 4 byte SMB value
BVAL(buf,pos) - extract a 8 byte SMB value
SVALS(buf,pos) - signed version of SVAL()
IVALS(buf,pos) - signed version of IVAL()
BVALS(buf,pos) - signed version of BVAL()

SSVAL(buf,pos,val) - put a 2 byte SMB value into a buffer
SIVAL(buf,pos,val) - put a 4 byte SMB value into a buffer
SBVAL(buf,pos,val) - put a 8 byte SMB value into a buffer
SSVALS(buf,pos,val) - signed version of SSVAL()
SIVALS(buf,pos,val) - signed version of SIVAL()
SBVALS(buf,pos,val) - signed version of SBVAL()

RSVAL(buf,pos) - like SVAL() but for NMB byte ordering
RSVALS(buf,pos) - like SVALS() but for NMB byte ordering
RIVAL(buf,pos) - like IVAL() but for NMB byte ordering
RIVALS(buf,pos) - like IVALS() but for NMB byte ordering
RSSVAL(buf,pos,val) - like SSVAL() but for NMB ordering
RSIVAL(buf,pos,val) - like SIVAL() but for NMB ordering
RSIVALS(buf,pos,val) - like SIVALS() but for NMB ordering

it also defines lots of intermediate macros, just ignore those :-)

*/


#define CVAL(buf,pos) ((unsigned int)(((const uint8_t *)(buf))[pos]))
#define CVAL_NC(buf,pos) (((uint8_t *)(buf))[pos]) /* Non-const version of CVAL */
#define PVAL(buf,pos) (CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL_NC(buf,pos) = (val))

#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf,pos,val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16_t)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32_t)IVAL(buf,pos))
#define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16_t)(val)))
#define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32_t)(val)))
#define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16_t)(val)))
#define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32_t)(val)))

/* 64 bit macros */
#define BVAL(p, ofs) (IVAL(p,ofs) | (((uint64_t)IVAL(p,(ofs)+4)) << 32))
#define BVALS(p, ofs) ((int64_t)BVAL(p,ofs))
#define SBVAL(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,((uint64_t)(v))>>32))
#define SBVALS(p, ofs, v) (SBVAL(p,ofs,(uint64_t)v))

/* now the reverse routines - these are used in nmb packets (mostly) */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))
#define BREV(x) ((IREV((uint64_t)x)<<32) | (IREV(((uint64_t)x)>>32)))

#define RSVAL(buf,pos) SREV(SVAL(buf,pos))
#define RSVALS(buf,pos) SREV(SVALS(buf,pos))
#define RIVAL(buf,pos) IREV(IVAL(buf,pos))
#define RIVALS(buf,pos) IREV(IVALS(buf,pos))
#define RBVAL(buf,pos) BREV(BVAL(buf,pos))
#define RBVALS(buf,pos) BREV(BVALS(buf,pos))
#define RSSVAL(buf,pos,val) SSVAL(buf,pos,SREV(val))
#define RSSVALS(buf,pos,val) SSVALS(buf,pos,SREV(val))
#define RSIVAL(buf,pos,val) SIVAL(buf,pos,IREV(val))
#define RSIVALS(buf,pos,val) SIVALS(buf,pos,IREV(val))
#define RSBVAL(buf,pos,val) SBVAL(buf,pos,BREV(val))
#define RSBVALS(buf,pos,val) SBVALS(buf,pos,BREV(val))

#endif /* _BYTEORDER_H */
