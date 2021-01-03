/*
 * Unix SMB/CIFS implementation.
 * Global contexts
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

#ifndef __GLOBAL_CONTEXTS_H__
#define __GLOBAL_CONTEXTS_H__

struct tevent_context;

struct tevent_context *global_event_context(void);
void global_event_context_free(void);

struct messaging_context;
struct messaging_context *global_messaging_context(void);
void global_messaging_context_free(void);

#endif
