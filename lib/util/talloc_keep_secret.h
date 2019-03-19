/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

#ifndef _TALLOC_KEEP_SECRET_H
#define _TALLOC_KEEP_SECRET_H

#ifdef DOXYGEN
/**
 * @brief Keep the memory secret when freeing.
 *
 * This can be used to define memory as secret. For example memory which holds
 * passwords or other secrets like session keys. The memory will be zeroed
 * before is being freed.
 *
 * If you duplicate memory, e.g. using talloc_strdup() or talloc_asprintf() you
 * need to call talloc_keep_secret() on the newly allocated memory too!
 *
 * @param[in]  ptr      The talloc chunk to mark as secure.
 *
 * @warning Do not use this in combination with talloc_realloc().
 */
void talloc_keep_secret(const void *ptr);
#else
#define talloc_keep_secret(ptr) _talloc_keep_secret(ptr, #ptr);
void _talloc_keep_secret(void *ptr, const char *name);
#endif

#endif /* _TALLOC_KEEP_SECRET_H */
