/*
 * Unix SMB/CIFS implementation.
 * Samba system utilities
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison  1998-2005
 * Copyright (C) Timur Bakeyev        2005
 * Copyright (C) Bjoern Jacke    2006-2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_SYS_RW_DATA_H__
#define __LIB_SYS_RW_DATA_H__

#include <unistd.h>

struct iovec;

ssize_t write_data_iov(int fd, const struct iovec *iov, int iovcnt);
ssize_t write_data(int fd, const void *buffer, size_t n);
ssize_t read_data(int fd, void *buffer, size_t n);

#endif
