/*
 * Unix SMB/CIFS implementation.
 *
 * test SMB2 multichannel operations
 *
 * Copyright (C) Guenther Deschner, 2016
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

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/cmdline/popt_common.h"
#include "libcli/security/security.h"
#include "libcli/resolve/resolve.h"
#include "lib/param/param.h"
#include "lib/events/events.h"
#include "oplock_break_handler.h"
#include "torture/smb2/block.h"

#define BASEDIR "multichanneltestdir"

#define CHECK_STATUS(status, correct) \
	torture_assert_ntstatus_equal_goto(tctx, status, correct,\
					   ret, done, "")

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s" \
				" got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = false; \
		goto done; \
	} } while (0)

#define CHECK_VAL_GREATER_THAN(v, gt_val) do { \
	if ((v) <= (gt_val)) { \
		torture_result(tctx, TORTURE_FAIL, \
				"(%s): wrong value for %s got 0x%x - " \
				"should be greater than 0x%x\n", \
				__location__, #v, (int)v, (int)gt_val); \
		ret = false; \
		goto done; \
	} } while (0)

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		CHECK_VAL((__io)->out.create_action,			\
				NTCREATEX_ACTION_ ## __created);	\
		CHECK_VAL((__io)->out.alloc_size, 0);			\
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while (0)

#define CHECK_PTR(ptr, correct) do { \
	if ((ptr) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s " \
				"got 0x%p - should be 0x%p\n", \
				__location__, #ptr, ptr, correct); \
		ret = false; \
		goto done; \
	} } while (0)

#define CHECK_LEASE(__io, __state, __oplevel, __key, __flags)		\
	do {								\
		CHECK_VAL((__io)->out.lease_response.lease_version, 1); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, \
					SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0],\
				  (__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1],\
				  ~(__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_state,\
				  smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level,\
				  SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0],\
				  0); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1],\
				  0); \
			CHECK_VAL((__io)->out.lease_response.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response.lease_flags, (__flags)); \
		CHECK_VAL((__io)->out.lease_response.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response.lease_epoch, 0); \
	} while (0)

static bool test_ioctl_network_interface_info(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      struct fsctl_net_iface_info *info)
{
	union smb_ioctl ioctl;
	struct smb2_handle fh;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip(tctx,
			    "server doesn't support SMB2_CAP_MULTI_CHANNEL\n");
	}

	ZERO_STRUCT(ioctl);

	ioctl.smb2.level = RAW_IOCTL_SMB2;

	fh.data[0] = UINT64_MAX;
	fh.data[1] = UINT64_MAX;

	ioctl.smb2.in.file.handle = fh;
	ioctl.smb2.in.function = FSCTL_QUERY_NETWORK_INTERFACE_INFO;
	/* Windows client sets this to 64KiB */
	ioctl.smb2.in.max_output_response = 0x10000;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	torture_assert_ntstatus_ok(tctx,
		smb2_ioctl(tree, tctx, &ioctl.smb2),
		"FSCTL_QUERY_NETWORK_INTERFACE_INFO failed");

	torture_assert(tctx,
		(ioctl.smb2.out.out.length != 0),
		"no interface info returned???");

	torture_assert_ndr_success(tctx,
		ndr_pull_struct_blob(&ioctl.smb2.out.out, tctx, info,
			(ndr_pull_flags_fn_t)ndr_pull_fsctl_net_iface_info),
		"failed to ndr pull");

	if (DEBUGLVL(1)) {
		NDR_PRINT_DEBUG(fsctl_net_iface_info, info);
	}

	return true;
}

static bool test_multichannel_interface_info(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	struct fsctl_net_iface_info info;

	return test_ioctl_network_interface_info(tctx, tree, &info);
}

static struct smb2_tree *test_multichannel_create_channel(
				struct torture_context *tctx,
				const char *host,
				const char *share,
				struct cli_credentials *credentials,
				struct smbcli_options *transport_options,
				struct smb2_tree *parent_tree
				)
{
	NTSTATUS status;
	struct smb2_transport *transport;
	struct smb2_session *session;
	bool ret = true;
	struct smb2_tree *tree;

	status = smb2_connect(tctx,
			host,
			lpcfg_smb_ports(tctx->lp_ctx),
			share,
			lpcfg_resolve_context(tctx->lp_ctx),
			credentials,
			&tree,
			tctx->ev,
			transport_options,
			lpcfg_socket_options(tctx->lp_ctx),
			lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			"smb2_connect failed");
	transport = tree->session->transport;
	transport->oplock.handler = torture_oplock_ack_handler;
	transport->oplock.private_data = tree;
	transport->lease.handler = torture_lease_handler;
	transport->lease.private_data = tree;
	torture_comment(tctx, "established transport [%p]\n", transport);

	/*
	 * If parent tree is set, bind the session to the parent transport
	 */
	if (parent_tree) {
		session = smb2_session_channel(transport,
				lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				parent_tree, parent_tree->session);
		torture_assert_goto(tctx, session != NULL, ret, done,
				"smb2_session_channel failed");

		tree->smbXcli = parent_tree->smbXcli;
		tree->session = session;
		status = smb2_session_setup_spnego(session,
						credentials,
						0 /* previous_session_id */);
		CHECK_STATUS(status, NT_STATUS_OK);
		torture_comment(tctx, "bound new session to parent\n");
	}
	/*
	 * We absolutely need to make sure to send something over this
	 * connection to register the oplock break handler with the smb client
	 * connection. If we do not send something (at least a keepalive), we
	 * will *NEVER* receive anything over this transport.
	 */
	smb2_keepalive(transport);

done:
	if (ret) {
		return tree;
	} else {
		return NULL;
	}
}

bool test_multichannel_create_channels(
				struct torture_context *tctx,
				const char *host,
				const char *share,
				struct cli_credentials *credentials,
				struct smbcli_options *transport_options,
				struct smb2_tree **tree2A,
				struct smb2_tree **tree2B,
				struct smb2_tree **tree2C
				)
{
	struct smb2_tree *tree;
	struct smb2_transport *transport2A;
	struct smb2_transport *transport2B;
	struct smb2_transport *transport2C;
	uint16_t local_port = 0;

	transport_options->client_guid = GUID_random();

	/* Session 2A */
	torture_comment(tctx, "Setting up connection 2A\n");
	tree = test_multichannel_create_channel(tctx, host, share,
				credentials, transport_options, NULL);
	if (!tree) {
		goto done;
	}
	*tree2A = tree;
	transport2A = tree->session->transport;
	local_port = torture_get_local_port_from_transport(transport2A);
	torture_comment(tctx, "transport2A uses tcp port: %d\n", local_port);

	/* Session 2B */
	if (tree2B) {
		torture_comment(tctx, "Setting up connection 2B\n");
		tree = test_multichannel_create_channel(tctx, host, share,
				credentials, transport_options, *tree2A);
		if (!tree) {
			goto done;
		}
		*tree2B = tree;
		transport2B = tree->session->transport;
		local_port = torture_get_local_port_from_transport(transport2B);
		torture_comment(tctx, "transport2B uses tcp port: %d\n",
								local_port);
	}

	/* Session 2C */
	if (tree2C) {
		torture_comment(tctx, "Setting up connection 2C\n");
		tree = test_multichannel_create_channel(tctx, host, share,
				credentials, transport_options, *tree2A);
		if (!tree) {
			goto done;
		}
		*tree2C = tree;
		transport2C = tree->session->transport;
		local_port = torture_get_local_port_from_transport(transport2C);
		torture_comment(tctx, "transport2C uses tcp port: %d\n",
								local_port);
	}

	return true;
done:
	return false;
}

static void test_multichannel_free_channels(struct smb2_tree *tree2A,
					     struct smb2_tree *tree2B,
					     struct smb2_tree *tree2C)
{
	TALLOC_FREE(tree2A);
	TALLOC_FREE(tree2B);
	TALLOC_FREE(tree2C);
}

static bool test_multichannel_initial_checks(struct torture_context *tctx,
					     struct smb2_tree *tree1)
{
	struct smb2_transport *transport1 = tree1->session->transport;
	uint32_t server_capabilities;
	struct fsctl_net_iface_info info;

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_skip_goto(tctx, fail,
				  "SMB 3.X Dialect family required for "
				  "Multichannel tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(
					tree1->session->transport->conn);
	if (!(server_capabilities & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip_goto(tctx, fail,
			     "Server does not support multichannel.");
	}

	torture_assert(tctx,
		test_ioctl_network_interface_info(tctx, tree1, &info),
		"failed to retrieve network interface info");

	return true;
fail:
	return false;
}

static void test_multichannel_init_smb_create(struct smb2_create *io)
{
	io->in.durable_open = false;
	io->in.durable_open_v2 = true;
	io->in.persistent_open = false;
	io->in.create_guid = GUID_random();
	io->in.timeout = 0x493E0; /* 300000 */
	/* windows 2016 returns 300000 0x493E0 */
}

/*
 * We simulate blocking incoming oplock break requests by simply ignoring
 * the incoming break requests.
 */
static bool test_set_ignore_break_handler(struct torture_context *tctx,
					  struct smb2_transport *transport)
{
	transport->oplock.handler = torture_oplock_ignore_handler;
	transport->lease.handler = torture_lease_ignore_handler;

	return true;
}

static bool test_reset_break_handler(struct torture_context *tctx,
				     struct smb2_transport *transport)
{
	transport->oplock.handler = torture_oplock_ack_handler;
	transport->lease.handler = torture_lease_handler;

	return true;
}

/*
 * Use iptables to block channels
 */
static bool test_iptables_block_channel(struct torture_context *tctx,
					struct smb2_transport *transport,
					const char *name)
{
	uint16_t local_port;
	bool ret;

	local_port = torture_get_local_port_from_transport(transport);
	torture_comment(tctx, "transport uses tcp port: %d\n", local_port);
	ret = torture_block_tcp_transport_name(tctx, transport, name);
	torture_assert(tctx, ret, "we could not block tcp transport");

	return ret;
}

static bool test_iptables_unblock_channel(struct torture_context *tctx,
					  struct smb2_transport *transport,
					  const char *name)
{
	uint16_t local_port;
	bool ret;

	local_port = torture_get_local_port_from_transport(transport);
	torture_comment(tctx, "transport uses tcp port: %d\n", local_port);
	ret = torture_unblock_tcp_transport_name(tctx, transport, name);
	torture_assert(tctx, ret, "we could not block tcp transport");

	return ret;
}

#define test_block_channel(_tctx, _t) _test_block_channel(_tctx, _t, #_t)
static bool _test_block_channel(struct torture_context *tctx,
					  struct smb2_transport *transport,
					  const char *name)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		return test_iptables_block_channel(tctx, transport, name);
	} else {
		return test_set_ignore_break_handler(tctx, transport);
	}
}

#define test_unblock_channel(_tctx, _t) _test_unblock_channel(_tctx, _t, #_t)
static bool _test_unblock_channel(struct torture_context *tctx,
					  struct smb2_transport *transport,
					  const char *name)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		return test_iptables_unblock_channel(tctx, transport, name);
	} else {
		return test_reset_break_handler(tctx, transport);
	}
}

static void test_cleanup_blocked_channels(struct torture_context *tctx)
{
	bool use_iptables = torture_setting_bool(tctx,
					"use_iptables", false);

	if (use_iptables) {
		torture_unblock_cleanup(tctx);
	}
}

/*
 * Oplock break - Test 1
 * Test to confirm that server sends oplock breaks as expected.
 * open file1 in session 2A
 * open file2 in session 2B
 * open file1 in session 1
 *      oplock break received
 * open file1 in session 1
 *      oplock break received
 * Cleanup
 */
static bool test_multichannel_oplock_break_test1(struct torture_context *tctx,
					   struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client1_file2 = {{0}};
	struct smb2_handle h_client1_file3 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_handle h_client2_file2 = {{0}};
	struct smb2_handle h_client2_file3 = {{0}};
	struct smb2_create io1, io2, io3;
	bool ret = true;
	const char *fname1 = BASEDIR "\\oplock_break_test1.dat";
	const char *fname2 = BASEDIR "\\oplock_break_test2.dat";
	const char *fname3 = BASEDIR "\\oplock_break_test3.dat";
	struct smb2_tree *tree2A = NULL;
	struct smb2_tree *tree2B = NULL;
	struct smb2_tree *tree2C = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Oplock break retry: Test1\n");

	torture_reset_break_info(tctx, &break_info);

	transport1->oplock.handler = torture_oplock_ack_handler;
	transport1->oplock.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io1, fname1,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	test_multichannel_init_smb_create(&io1);

	smb2_oplock_create_share(&io2, fname2,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	test_multichannel_init_smb_create(&io2);

	smb2_oplock_create_share(&io3, fname3,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	test_multichannel_init_smb_create(&io3);

	transport2_options = transport1->options;

	ret = test_multichannel_create_channels(tctx, host, share,
						  credentials,
						  &transport2_options,
						  &tree2A, &tree2B, NULL);
	torture_assert(tctx, ret, "Could not create channels.\n");

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via session 2A\n");
	status = smb2_create(tree2A, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	/* 2b opens file2 */
	torture_comment(tctx, "client2 opens fname2 via session 2B\n");
	status = smb2_create(tree2B, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);


	/* 1 opens file1 - batchoplock break? */
	torture_comment(tctx, "client1 opens fname1 via session 1\n");
	io1.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("s"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);

	torture_reset_break_info(tctx, &break_info);

	/* 1 opens file2 - batchoplock break? */
	torture_comment(tctx, "client1 opens fname2 via session 1\n");
	io2.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree1, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("s"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);

	/* cleanup everything */
	torture_reset_break_info(tctx, &break_info);

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);
	smb2_util_close(tree2A, h_client2_file1);
	smb2_util_close(tree2A, h_client2_file2);
	smb2_util_close(tree2A, h_client2_file3);

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	CHECK_VAL(break_info.count, 0);
	test_multichannel_free_channels(tree2A, tree2B, tree2C);
	tree2A = tree2B = tree2C = NULL;
done:
	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);
	if (tree2A != NULL) {
		smb2_util_close(tree2A, h_client2_file1);
		smb2_util_close(tree2A, h_client2_file2);
		smb2_util_close(tree2A, h_client2_file3);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	smb2_deltree(tree1, BASEDIR);

	test_multichannel_free_channels(tree2A, tree2B, tree2C);
	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_multichannel_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "multichannel");
	struct torture_suite *suite_generic = torture_suite_create(ctx,
								   "generic");
	struct torture_suite *suite_oplocks = torture_suite_create(ctx,
								   "oplocks");

	torture_suite_add_suite(suite, suite_generic);
	torture_suite_add_suite(suite, suite_oplocks);

	torture_suite_add_1smb2_test(suite, "interface_info",
				     test_multichannel_interface_info);
	torture_suite_add_1smb2_test(suite_oplocks, "test1",
				     test_multichannel_oplock_break_test1);

	suite->description = talloc_strdup(suite, "SMB2 Multichannel tests");

	return suite;
}
