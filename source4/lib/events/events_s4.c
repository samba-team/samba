/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"
#include "events.h"
#include "events_internal.h"

NTSTATUS s4_events_standard_init(void)
{
       if (!events_standard_init()) {
               return NT_STATUS_INTERNAL_ERROR;
       }
       return NT_STATUS_OK;
}

NTSTATUS s4_events_select_init(void)
{
       if (!events_select_init()) {
               return NT_STATUS_INTERNAL_ERROR;
       }
       return NT_STATUS_OK;
}

#if HAVE_EVENTS_EPOLL
NTSTATUS s4_events_epoll_init(void)
{
       if (!events_epoll_init()) {
               return NT_STATUS_INTERNAL_ERROR;
       }
       return NT_STATUS_OK;
}
#endif

#if HAVE_LINUX_AIO
NTSTATUS s4_events_aio_init(void)
{
       if (!events_aio_init()) {
               return NT_STATUS_INTERNAL_ERROR;
       }
       return NT_STATUS_OK;
}
#endif
