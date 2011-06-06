#ifndef __LIB_EVENTS_H__
#define __LIB_EVENTS_H__
/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

#define TEVENT_COMPAT_DEFINES 1
#include <tevent.h>
struct tevent_context *s4_event_context_init(TALLOC_CTX *mem_ctx);
struct tevent_context *event_context_find(TALLOC_CTX *mem_ctx) _DEPRECATED_;
void s4_event_context_set_default(struct tevent_context *ev);
#endif /* __LIB_EVENTS_H__ */
