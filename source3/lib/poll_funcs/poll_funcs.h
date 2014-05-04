/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013
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

/**
 * @file poll_funcs.h
 *
 * @brief event loop abstraction
 */

/*
 * This is inspired by AvahiWatch, the avahi event loop abstraction.
 */

#ifndef __POLL_FUNCS_H__
#define __POLL_FUNCS_H__

#include "replace.h"

/**
 * poll_watch and poll_timeout are undefined here, every implementation can
 * implement its own structures.
 */

struct poll_watch;
struct poll_timeout;

struct poll_funcs {

	/**
	 * @brief Create a new file descriptor watch
	 *
	 * @param[in] funcs The callback array
	 * @param[in] fd The fd to watch
	 * @param[in] events POLLIN and POLLOUT or'ed together
	 * @param[in] callback Function to call by the implementation
	 * @param[in] private_data Pointer to give back to callback
	 *
	 * @return A new poll_watch struct
	 */

	struct poll_watch *(*watch_new)(
		const struct poll_funcs *funcs, int fd, short events,
		void (*callback)(struct poll_watch *w, int fd,
				 short events, void *private_data),
		void *private_data);

	/**
	 * @brief Change the watched events for a struct poll_watch
	 *
	 * @param[in] w The poll_watch to change
	 * @param[in] events new POLLIN and POLLOUT or'ed together
	 */

	void (*watch_update)(struct poll_watch *w, short events);

	/**
	 * @brief Read events currently watched
	 *
	 * @param[in] w The poll_watch to inspect
	 *
	 * @returns The events currently watched
	 */

	short (*watch_get_events)(struct poll_watch *w);

	/**
	 * @brief Free a struct poll_watch
	 *
	 * @param[in] w The poll_watch struct to free
	 */

	void (*watch_free)(struct poll_watch *w);


	/**
	 * @brief Create a new timeout watch
	 *
	 * @param[in] funcs The callback array
	 * @param[in] tv The time when the timeout should trigger
	 * @param[in] callback Function to call at time "ts"
	 * @param[in] private_data Pointer to give back to callback
	 *
	 * @return A new poll_timeout struct
	 */

	struct poll_timeout *(*timeout_new)(
		const struct poll_funcs *funcs, const struct timeval *tv,
		void (*callback)(struct poll_timeout *t, void *private_data),
		void *private_data);

	/**
	 * @brief Change the timeout of a watch
	 *
	 * @param[in] t The timeout watch to change
	 * @param[in] ts The new trigger time
	 */

	void (*timeout_update)(struct poll_timeout *t,
			       const struct timespec *ts);

	/**
	 * @brief Free a poll_timeout
	 *
	 * @param[in] t The poll_timeout to free
	 */

	void (*timeout_free)(struct poll_timeout *t);

	/**
	 * @brief private data for use by the implementation
	 */

	void *private_data;
};

#endif
