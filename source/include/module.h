/*
   Unix SMB/CIFS implementation.
   Handling of idle/exit events
   Copyright (C) Jelmer Vernooij 2003

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

#ifndef _MODULE_H
#define _MODULE_H

/* Module support */
typedef NTSTATUS (*init_module_function) (void);

/* Module that registers a backend for a certain subsystem */
typedef NTSTATUS (*register_backend_function) (const void *data);

#endif /* _MODULE_H */
