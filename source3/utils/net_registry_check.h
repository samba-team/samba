/*
 * Samba Unix/Linux SMB client library
 *
 * Copyright (C) Gregor Beck 2011
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
 * @brief  Check the registry database.
 * @author Gregor Beck <gb@sernet.de>
 * @date   Jun 2011
 */

#ifndef NET_REGISTRY_CHECK_H
#define NET_REGISTRY_CHECK_H

#include <stdbool.h>

struct net_context;

struct check_options {
	bool test;
	bool verbose;
	bool lock;
	bool automatic;
	bool force;
	bool repair;
	int version;
	const char *output;
	bool wipe;
	bool implicit_db;
};

int net_registry_check_db(const char* db, const struct check_options* opts);

#endif /* NET_REGISTRY_CHECK_H */

/*Local Variables:*/
/*mode: c*/
/*End:*/
