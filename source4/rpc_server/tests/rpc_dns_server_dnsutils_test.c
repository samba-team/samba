/*
 * Unit tests for source4/rpc_server/dnsserver/dnsutils.c
 *
 *  Copyright (C) Catalyst.NET Ltd 2018
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
 *
 */

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


#include "../dnsserver/dnsutils.c"


/*
 * Test setting of an empty ZONE_MASTER_SERVERS property
 */
static void test_dnsserver_init_zoneinfo_master_servers_empty(void **state)
{
	struct dnsserver_zone *zone = NULL;
	struct dnsserver_serverinfo *serverinfo = NULL;
	struct dnsserver_zoneinfo *zoneinfo = NULL;
	struct dnsp_DnsProperty *property = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Setup the zone data
	 */
	zone = talloc_zero(ctx, struct dnsserver_zone);
	assert_non_null(zone);
	zone->name = "test";

	/*
	 * Set up an empty ZONE_MASTER_SERVERS property
	 */
	property = talloc_zero_array(ctx, struct dnsp_DnsProperty, 1);
	assert_non_null(property);
	property->id = DSPROPERTY_ZONE_MASTER_SERVERS;
	property->data.master_servers.addrCount = 0;
	property->data.master_servers.addrArray = NULL;

	zone->tmp_props = property;
	zone->num_props = 1;


	/*
	 * Setup the server info
	 */
	serverinfo = talloc_zero(ctx, struct dnsserver_serverinfo);
	assert_non_null(serverinfo);

	/*
	 * call dnsserver_init_zoneinfo
	 */
	zoneinfo = dnsserver_init_zoneinfo(zone, serverinfo);

	/*
	 * Check results
	 */
	assert_non_null(zoneinfo);
	assert_non_null(zoneinfo->aipLocalMasters);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrCount, 0);
	assert_null(zoneinfo->aipLocalMasters->AddrArray);

	TALLOC_FREE(ctx);
}

/*
 * Test setting of a non empty ZONE_MASTER_SERVERS property
 */
static void test_dnsserver_init_zoneinfo_master_servers(void **state)
{
	struct dnsserver_zone *zone = NULL;
	struct dnsserver_serverinfo *serverinfo = NULL;
	struct dnsserver_zoneinfo *zoneinfo = NULL;
	struct dnsp_DnsProperty *property = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Setup the zone data
	 */
	zone = talloc_zero(ctx, struct dnsserver_zone);
	assert_non_null(zone);
	zone->name = "test";

	/*
	 * Set up an empty ZONE_MASTER_SERVERS property
	 */
	property = talloc_zero_array(ctx, struct dnsp_DnsProperty, 1);
	assert_non_null(property);
	property->id = DSPROPERTY_ZONE_MASTER_SERVERS;
	property->data.master_servers.addrCount = 4;
	property->data.master_servers.addrArray =
		talloc_zero_array(ctx, uint32_t, 4);
	property->data.master_servers.addrArray[0] = 1000;
	property->data.master_servers.addrArray[1] = 1001;
	property->data.master_servers.addrArray[2] = 1002;
	property->data.master_servers.addrArray[3] = 1003;

	zone->tmp_props = property;
	zone->num_props = 1;


	/*
	 * Setup the server info
	 */
	serverinfo = talloc_zero(ctx, struct dnsserver_serverinfo);
	assert_non_null(serverinfo);

	/*
	 * call dnsserver_init_zoneinfo
	 */
	zoneinfo = dnsserver_init_zoneinfo(zone, serverinfo);

	/*
	 * Check results
	 */
	assert_non_null(zoneinfo);
	assert_non_null(zoneinfo->aipLocalMasters);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrCount, 4);
	assert_non_null(zoneinfo->aipLocalMasters->AddrArray);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[0], 1000);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[1], 1001);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[2], 1002);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[3], 1003);

	/*
	 * Ensure that we're working with a copy of the property data
	 * and not a reference.
	 * The pointers should be different, and we should be able to change
	 * the values in the property without affecting the zoneinfo data
	 */
	assert_true(zoneinfo->aipLocalMasters->AddrArray !=
		    property->data.master_servers.addrArray);
	property->data.master_servers.addrArray[0] = 0;
	property->data.master_servers.addrArray[1] = 1;
	property->data.master_servers.addrArray[2] = 2;
	property->data.master_servers.addrArray[3] = 3;
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[0], 1000);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[1], 1001);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[2], 1002);
	assert_int_equal(zoneinfo->aipLocalMasters->AddrArray[3], 1003);

	TALLOC_FREE(ctx);
}

/*
 * Test setting of an empty ZONE_SCAVENGING_SERVERS property
 */
static void test_dnsserver_init_zoneinfo_scavenging_servers_empty(void **state)
{
	struct dnsserver_zone *zone = NULL;
	struct dnsserver_serverinfo *serverinfo = NULL;
	struct dnsserver_zoneinfo *zoneinfo = NULL;
	struct dnsp_DnsProperty *property = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Setup the zone data
	 */
	zone = talloc_zero(ctx, struct dnsserver_zone);
	assert_non_null(zone);
	zone->name = "test";

	property = talloc_zero_array(ctx, struct dnsp_DnsProperty, 1);
	assert_non_null(property);
	property->id = DSPROPERTY_ZONE_SCAVENGING_SERVERS;
	property->data.servers.addrCount = 0;
	property->data.servers.addrArray = NULL;

	zone->tmp_props = property;
	zone->num_props = 1;


	serverinfo = talloc_zero(ctx, struct dnsserver_serverinfo);
	assert_non_null(serverinfo);

	zoneinfo = dnsserver_init_zoneinfo(zone, serverinfo);

	assert_non_null(zoneinfo);
	assert_non_null(zoneinfo->aipScavengeServers);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrCount, 0);
	assert_null(zoneinfo->aipScavengeServers->AddrArray);

	TALLOC_FREE(ctx);
}

/*
 * Test setting of a non empty ZONE_SCAVENGING_SERVERS property
 */
static void test_dnsserver_init_zoneinfo_scavenging_servers(void **state)
{
	struct dnsserver_zone *zone = NULL;
	struct dnsserver_serverinfo *serverinfo = NULL;
	struct dnsserver_zoneinfo *zoneinfo = NULL;
	struct dnsp_DnsProperty *property = NULL;

	TALLOC_CTX *ctx = talloc_new(NULL);

	/*
	 * Setup the zone data
	 */
	zone = talloc_zero(ctx, struct dnsserver_zone);
	assert_non_null(zone);
	zone->name = "test";

	property = talloc_zero_array(ctx, struct dnsp_DnsProperty, 1);
	assert_non_null(property);
	property->id = DSPROPERTY_ZONE_SCAVENGING_SERVERS;
	property->data.servers.addrCount = 4;
	property->data.servers.addrArray = talloc_zero_array(ctx, uint32_t, 4);
	property->data.servers.addrArray[0] = 1000;
	property->data.servers.addrArray[1] = 1001;
	property->data.servers.addrArray[2] = 1002;
	property->data.servers.addrArray[3] = 1003;

	zone->tmp_props = property;
	zone->num_props = 1;


	serverinfo = talloc_zero(ctx, struct dnsserver_serverinfo);
	assert_non_null(serverinfo);

	zoneinfo = dnsserver_init_zoneinfo(zone, serverinfo);

	assert_non_null(zoneinfo);
	assert_non_null(zoneinfo->aipScavengeServers);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrCount, 4);
	assert_non_null(zoneinfo->aipScavengeServers->AddrArray);
	assert_non_null(zoneinfo->aipScavengeServers->AddrArray);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[0], 1000);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[1], 1001);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[2], 1002);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[3], 1003);

	/*
	 * Ensure that we're working with a copy of the property data
	 * and not a reference.
	 * The pointers should be different, and we should be able to change
	 * the values in the property without affecting the zoneinfo data
	 */
	assert_true(zoneinfo->aipScavengeServers->AddrArray !=
		    property->data.servers.addrArray);
	property->data.servers.addrArray[0] = 0;
	property->data.servers.addrArray[1] = 1;
	property->data.servers.addrArray[2] = 2;
	property->data.servers.addrArray[3] = 3;
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[0], 1000);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[1], 1001);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[2], 1002);
	assert_int_equal(zoneinfo->aipScavengeServers->AddrArray[3], 1003);


	TALLOC_FREE(ctx);
}
int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(
		    test_dnsserver_init_zoneinfo_master_servers_empty),
		cmocka_unit_test(
		    test_dnsserver_init_zoneinfo_master_servers),
		cmocka_unit_test(
		    test_dnsserver_init_zoneinfo_scavenging_servers_empty),
		cmocka_unit_test(
		    test_dnsserver_init_zoneinfo_scavenging_servers),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
