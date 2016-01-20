/*
   Unix SMB/CIFS implementation.
   Poll glib event loop from tevent

   Copyright (C) Ralph Boehme 2016

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TEVENT_GLIB_GLUE_H
#define _TEVENT_GLIB_GLUE_H

#include <talloc.h>
#include <tevent.h>

/**
 * @brief Add a glib GmainContext to a tevent context
 *
 * tevent will poll the glib event sources and run handlers for
 * pending events as detailed in the glib documentation:
 *
 * https://developer.gnome.org/glib/stable/glib-The-Main-Event-Loop.html
 *
 * If tevent was built without glib support, this function will always return
 * NULL with an error number ENOSYS.
 *
 * @param[in]  mem_ctx          Memory context to use
 *
 * @param[in]  ev               Event context to use
 *
 * @param[in]  gmain_ctx        GMainContext that will be added to tevent
 *
 * @return                      A handle on the glue context that binds the
 *                              the GMainContext to tevent. Pass the glue handle to
 *                              tevent_glib_glue_quit() in a callback when you want
 *                              stop processing glib events.
 *                              You must not call talloc_free() on the handle while
 *                              the loop is still in use and attached to tevent.
 */
struct tevent_glib_glue *samba_tevent_glib_glue_create(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       GMainContext *gmain_ctx);

/**
 * @brief Stop polling a GMainContext
 *
 * Used in a callback when you want to stop processing glib events.
 *
 * @param[in]  glue             And tevent_glib_glue handle
 */
void samba_tevent_glib_glue_quit(struct tevent_glib_glue *glue);

#endif
