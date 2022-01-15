/*
   CTDB cluster config handling

   Copyright (C) Martin Schwenke  2018

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

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"

#include "common/conf.h"

#include "cluster_conf.h"

#define CLUSTER_TRANSPORT_DEFAULT "tcp"

/*
 * Ideally this wants to be a void function but it also used directly
 * as a validation function
 */
static bool check_static_string_change(const char *key,
				       const char *old_value,
				       const char *new_value,
				       enum conf_update_mode mode)
{
	if (mode == CONF_MODE_RELOAD) {
		if (old_value == new_value) {
			goto done;
		}

		/*
		 * At this point old_value or new_value can not both
		 * NULL, so if one is NULL then they are different
		 */
		if (old_value == NULL ||
		    new_value == NULL ||
		    strcmp(old_value, new_value) != 0) {
			D_WARNING("Ignoring update of [%s] -> %s\n",
				  CLUSTER_CONF_SECTION,
				  key);
		}
	}

done:
	return true;
}

static bool validate_transport(const char *key,
			       const char *old_transport,
			       const char *new_transport,
			       enum conf_update_mode mode)
{
	/* Don't allow "ib" for now.  It is broken! */
	if (strcmp(new_transport, CLUSTER_TRANSPORT_DEFAULT) != 0) {
		D_ERR("Invalid value for [cluster] -> transport = %s\n",
		      new_transport);
		return false;
	}

	/* This sometimes warns but always returns true */
	return check_static_string_change(key,
					  old_transport,
					  new_transport,
					  mode);
}

static bool validate_node_address(const char *key,
				  const char *old_node_address,
				  const char *new_node_address,
				  enum conf_update_mode mode)
{
	struct in_addr addr4;
	struct in6_addr addr6;
	int ret;

	if (new_node_address == NULL) {
		goto good;
	}

	ret = inet_pton(AF_INET, new_node_address, &addr4);
	if (ret == 1) {
		goto good;
	}

	ret = inet_pton(AF_INET6, new_node_address, &addr6);
	if (ret == 1) {
		goto good;
	}

	D_ERR("Invalid value for [cluster] -> node address = %s\n",
	      new_node_address);
	return false;

good:
	/* This sometimes warns but always returns true */
	return check_static_string_change(key,
					  old_node_address,
					  new_node_address,
					  mode);
}

static bool validate_recovery_lock(const char *key,
				   const char *old_reclock,
				   const char *new_reclock,
				   enum conf_update_mode mode)
{
	bool status;

	if (new_reclock != NULL) {
		D_WARNING("Configuration option [%s] -> %s is deprecated\n",
			  CLUSTER_CONF_SECTION,
			  key);
	}

	status = check_static_string_change(key, old_reclock, new_reclock, mode);

	return status;
}

static bool validate_leader_timeout(const char *key,
				    int old_timeout,
				    int new_timeout,
				    enum conf_update_mode mode)
{
	if (new_timeout <= 0) {
		D_ERR("Invalid value for [cluster] -> leader timeout = %d\n",
		      new_timeout);
		return false;
	}

	return true;
}

void cluster_conf_init(struct conf_context *conf)
{
	conf_define_section(conf, CLUSTER_CONF_SECTION, NULL);

	conf_define_string(conf,
			   CLUSTER_CONF_SECTION,
			   CLUSTER_CONF_TRANSPORT,
			   CLUSTER_TRANSPORT_DEFAULT,
			   validate_transport);
	conf_define_string(conf,
			   CLUSTER_CONF_SECTION,
			   CLUSTER_CONF_NODE_ADDRESS,
			   NULL,
			   validate_node_address);
	conf_define_string(conf,
			   CLUSTER_CONF_SECTION,
			   CLUSTER_CONF_CLUSTER_LOCK,
			   NULL,
			   check_static_string_change);
	conf_define_string(conf,
			   CLUSTER_CONF_SECTION,
			   CLUSTER_CONF_RECOVERY_LOCK,
			   NULL,
			   validate_recovery_lock);
	conf_define_integer(conf,
			    CLUSTER_CONF_SECTION,
			    CLUSTER_CONF_LEADER_TIMEOUT,
			    5,
			    validate_leader_timeout);
	conf_define_boolean(conf,
			    CLUSTER_CONF_SECTION,
			    CLUSTER_CONF_LEADER_CAPABILITY,
			    true,
			    NULL);
}
