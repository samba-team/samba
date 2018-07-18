/*
   Line based I/O over fds

   Copyright (C) Amitay Isaacs  2018

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

#ifndef __CTDB_LINE_H__
#define __CTDB_LINE_H__

#include <talloc.h>

/**
 * @file line.h
 *
 * @brief Line based I/O over pipes and sockets
 */

/**
 * @brief The callback routine called to process a line
 *
 * @param[in]  line The line read
 * @param[in]  private_data Private data for callback
 * @return 0 to continue processing lines, non-zero to stop reading
 */
typedef int (*line_process_fn_t)(char *line, void *private_data);

/**
 * @brief Read a line (terminated by \n or \0)
 *
 * If there is any read error on fd, then errno will be returned.
 * If callback function returns a non-zero value, then that value will be
 * returned.
 *
 * @param[in]  fd The file descriptor
 * @param[in]  length The expected length of a line (this is only a hint)
 * @param[in]  mem_ctx Talloc memory context
 * @param[in]  callback Callback function called when a line is read
 * @param[in]  private_data Private data for callback
 * @param[out] num_lines Number of lines read so far
 * @return 0 on on success, errno on failure
 */
int line_read(int fd,
	      size_t length,
	      TALLOC_CTX *mem_ctx,
	      line_process_fn_t callback,
	      void *private_data,
	      int *num_lines);

#endif /* __CTDB_LINE_H__ */
