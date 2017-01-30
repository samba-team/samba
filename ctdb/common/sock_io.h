/*
   Generic Socket I/O

   Copyright (C) Amitay Isaacs  2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_SOCK_IO_H__
#define __CTDB_SOCK_IO_H__

typedef void (*sock_queue_callback_fn_t)(uint8_t *buf, size_t buflen,
					 void *private_data);

struct sock_queue;

bool sock_clean(const char *sockpath);
int sock_connect(const char *sockpath);

struct sock_queue *sock_queue_setup(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd,
				    sock_queue_callback_fn_t callback,
				    void *private_data);

int sock_queue_write(struct sock_queue *queue, uint8_t *buf, size_t buflen);

#endif /* __CTDB_SOCK_IO_H__ */
