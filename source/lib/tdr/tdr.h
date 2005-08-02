/* 
   Unix SMB/CIFS implementation.
   TDR definitions
   Copyright (C) Jelmer Vernooij 2005
   
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

#define TDR_FLAG_BIGENDIAN		1

struct tdr_pull {
	uint8_t *data;
	uint32_t offset;
	uint32_t length;
	int flags;
};

struct tdr_push {
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;
	uint32_t length;
	int flags;
};

struct tdr_print {
	int level;
	void (*print)(struct tdr_print *, const char *, ...);
};

#define TDR_CHECK(call) do { NTSTATUS _status; \
                             _status = call; \
                             if (!NT_STATUS_IS_OK(_status)) \
                                return _status; \
                        } while (0)

#define TDR_ALLOC(tdr, s, n) do { \
	                       (s) = talloc_array_size(tdr, sizeof(*(s)), n); \
                           if ((n) && !(s)) return NT_STATUS_NO_MEMORY; \
                           } while (0)
