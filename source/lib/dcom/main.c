/*
   Unix SMB/CIFS implementation.
   Main DCOM functionality
   Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>

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

void CoInitializeEx(void *reserved, uint32 thread_options)
{
	/* FIXME */
}

void CoInitialize(void *reserved)
{
	CoInitializeEx(reserved, 0);
}

void CoUnitialize(void)
{
	/* FIXME */
}

void CoRegisterClassObject(void)
{
	/* FIXME */
}

void CoUnregisterClassObject(void)
{
	/* FIXME */
}

void CoCreateInstanceEx(struct GUID *clsid, void *iface, uint32 context, struct COSERVERINFO *pcsi, uint32 num, struct MULTI_QI *results)
{
	/* FIXME: Connect to remote server and :*/

	/* FIXME: Call RemoteActivation() */
	/* FIXME: Call ServerAlive() on IOXIDResolver */

}

void CoCreateInstance(void)
{
	CoCreateInstanceEx(/*FIXME*/);
}

void CoRegisterClassObject(void)
{
	/* FIXME */
}
