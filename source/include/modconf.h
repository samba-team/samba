#ifndef _MODCONF_H_
#define _MODCONF_H_
/* 
   Unix SMB/CIFS implementation.

   ModConf headers

   Copyright (C) Simo Sorce 2003
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#define SAMBA_CONFIG_INTERFACE_VERSION	1

/* Filled out by config backends */
struct config_functions {
	NTSTATUS (*init)(char *params);
	NTSTATUS (*load)(BOOL (*sfunc)(const char *),BOOL (*pfunc)(const char *, const char *));
	NTSTATUS (*close)(void);
};
#endif /* _MODCONF_H_ */
