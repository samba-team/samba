/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   printcap parsing
   Copyright (C) Karl Auer 1993, 1994
   
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

/*
 *
 * Prototypes etc for pcap.c.
 *
 */
#ifndef _PCAP_H
#define _PCAP_H

#include "smb.h"

extern BOOL pcap_printername_ok(char *pszPrintername, char *pszPrintcapname);
extern void pcap_printer_fn(void (*fn)());

#endif
