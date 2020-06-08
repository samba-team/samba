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
#include "lease_break_handler.h"
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

#define CHECK_LEASE_V2(__io, __state, __oplevel, __key, __flags, __parent, __epoch) \
	do {								\
		CHECK_VAL((__io)->out.lease_response_v2.lease_version, 2); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response_v2.lease_flags, __flags); \
		if (__flags & SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) { \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[0], (__parent)); \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[1], ~(__parent)); \
		} \
		CHECK_VAL((__io)->out.lease_response_v2.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response_v2.lease_epoch, (__epoch)); \
	} while(0)

#define CHECK_LEASE_BREAK_V2(__lb, __key, __from, __to, __break_flags, __new_epoch) \
	do {								\
		CHECK_VAL((__lb).current_lease.lease_key.data[0], (__key)); \
		CHECK_VAL((__lb).current_lease.lease_key.data[1], ~(__key)); \
		CHECK_VAL((__lb).current_lease.lease_state, smb2_util_lease_state(__from)); \
		CHECK_VAL((__lb).new_epoch, (__new_epoch)); \
		CHECK_VAL((__lb).break_flags, (__break_flags)); \
		CHECK_VAL((__lb).new_lease_state, smb2_util_lease_state(__to)); \
	} while(0)

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
				const struct smbcli_options *_transport_options,
				struct smb2_tree *parent_tree
				)
{
	struct smbcli_options transport_options = *_transport_options;
	NTSTATUS status;
	struct smb2_transport *transport;
	struct smb2_session *session;
	bool ret = true;
	struct smb2_tree *tree;

	if (parent_tree) {
		transport_options.only_negprot = true;
	}

	status = smb2_connect(tctx,
			host,
			lpcfg_smb_ports(tctx->lp_ctx),
			share,
			lpcfg_resolve_context(tctx->lp_ctx),
			credentials,
			&tree,
			tctx->ev,
			&transport_options,
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

bool test_multichannel_create_channel_array(
				struct torture_context *tctx,
				const char *host,
				const char *share,
				struct cli_credentials *credentials,
				struct smbcli_options *transport_options,
				uint8_t num_trees,
				struct smb2_tree **trees)
{
	uint8_t i;

	transport_options->client_guid = GUID_random();

	for (i = 0; i < num_trees; i++) {
		struct smb2_tree *parent_tree = NULL;
		struct smb2_tree *tree = NULL;
		struct smb2_transport *transport = NULL;
		uint16_t local_port = 0;

		if (i > 0) {
			parent_tree = trees[0];
		}

		torture_comment(tctx, "Setting up connection %d\n", i);
		tree = test_multichannel_create_channel(tctx, host, share,
					credentials, transport_options,
					parent_tree);
		torture_assert(tctx, tree, "failed to created new channel");

		trees[i] = tree;
		transport = tree->session->transport;
		local_port = torture_get_local_port_from_transport(transport);
		torture_comment(tctx, "transport[%d] uses tcp port: %d\n",
				i, local_port);
	}

	return true;
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
	struct smb2_tree **trees = NULL;
	size_t num_trees = 0;
	bool ret;

	torture_assert(tctx, tree2A, "tree2A required!");
	num_trees += 1;
	torture_assert(tctx, tree2B, "tree2B required!");
	num_trees += 1;
	if (tree2C != NULL) {
		num_trees += 1;
	}
	trees = talloc_zero_array(tctx, struct smb2_tree *, num_trees);
	torture_assert(tctx, trees, "out of memory");

	ret = test_multichannel_create_channel_array(tctx, host, share, credentials,
						     transport_options,
						     num_trees, trees);
	if (!ret) {
		return false;
	}

	*tree2A = trees[0];
	*tree2B = trees[1];
	if (tree2C != NULL) {
		*tree2C = trees[2];
	}

	return true;
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

/* Timer handler function notifies the registering function that time is up */
static void timeout_cb(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	bool *timesup = (bool *)private_data;
	*timesup = true;
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

/*
 * Oplock Break Test 2
 * Test to see if oplock break retries are sent by the server.
 * Also checks to see if new channels can be created and used
 * after an oplock break retry.
 * open file1 in 2A
 * open file2 in 2B
 * open file1 in session 1
 *      oplock break received
 * block channel on which oplock break received
 * open file2 in session 1
 *      oplock break not received. Retry received.
 *      file opened
 * write to file2 on 2B
 *      Break sent to session 1(which has file2 open)
 *      Break sent to session 2A(which has read oplock)
 * close file1 in session 1
 * open file1 with session 1
 * unblock blocked channel
 * disconnect blocked channel
 * connect channel 2D
 * open file3 in 2D
 * open file3 in session 1
 *      receive break
 */
static bool test_multichannel_oplock_break_test2(struct torture_context *tctx,
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
	struct smb2_tree *tree2D = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2 = NULL;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	DATA_BLOB blob;
	bool block_setup = false;
	bool block_ok = false;
	bool unblock_ok = false;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Oplock break retry: Test2\n");

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
						  &tree2A, &tree2B, &tree2C);
	torture_assert(tctx, ret, "Could not create channels.\n");

	torture_comment(tctx, "client2 opens fname1 via session 2A\n");
	io1.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree2A, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);


	torture_comment(tctx, "client2 opens fname2 via session 2B\n");
	io2.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree2B, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);


	torture_comment(tctx, "client1 opens fname1 via session 1\n");
	io1.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("s"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);

	/* We use the transport over which this oplock break was received */
	transport2 = break_info.received_transport;
	torture_reset_break_info(tctx, &break_info);

	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");

	/* block channel */
	block_ok = test_block_smb2_transport(tctx, transport2);

	torture_comment(tctx, "client1 opens fname2 via session 1\n");
	io2.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree1, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("s"));

	/*
	 * Samba downgrades oplock to a level 2 oplock.
	 * Windows 2016 revokes oplock
	 */
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);
	torture_reset_break_info(tctx, &break_info);

	torture_comment(tctx, "Trying write to file2 on tree2B\n");

	blob = data_blob_string_const("Here I am");
	status = smb2_util_write(tree2B,
				 h_client2_file2,
				 blob.data,
				 0,
				 blob.length);
	torture_assert_ntstatus_ok(tctx, status,
		"failed to write file2 via channel 2B");

	/*
	 * Samba: Write triggers 2 oplock breaks
	 *  for session 1 which has file2 open
	 *  for session 2 which has type 2 oplock
	 * Windows 2016: Only one oplock break for session 1
	 */
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL_GREATER_THAN(break_info.count, 0);
	torture_reset_break_info(tctx, &break_info);

	torture_comment(tctx, "client1 closes fname2 via session 1\n");
	smb2_util_close(tree1, h_client1_file2);

	torture_comment(tctx, "client1 opens fname2 via session 1 again\n");
	io2.in.oplock_level = smb2_util_oplock_level("b");
	status = smb2_create(tree1, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file2 = io2.out.file.handle;
	io2.out.alloc_size = 0;
	io2.out.size = 0;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("s"));

	/*
	 * now add a fourth channel and repeat the test, we need to reestablish
	 * transport2 because the remote end has invalidated our connection
	 */
	torture_comment(tctx, "Connecting session 2D\n");
	tree2D = test_multichannel_create_channel(tctx, host, share,
				     credentials, &transport2_options, tree2B);
	if (!tree2D) {
		goto done;
	}

	torture_reset_break_info(tctx, &break_info);
	torture_comment(tctx, "client 2 opening fname3 over transport2D\n");
	status = smb2_create(tree2D, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io3.out.oplock_level, smb2_util_oplock_level("b"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 0);

	torture_comment(tctx, "client1 opens fname3 via session 1\n");
	status = smb2_create(tree1, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io3.out.oplock_level, smb2_util_oplock_level("s"));
	torture_wait_for_oplock_break(tctx);
	CHECK_VAL(break_info.count, 1);

done:
	if (block_ok && !unblock_ok) {
		test_unblock_smb2_transport(tctx, transport2);
	}
	test_cleanup_blocked_transports(tctx);

	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);
	if (tree2B != NULL) {
		smb2_util_close(tree2B, h_client2_file1);
		smb2_util_close(tree2B, h_client2_file2);
		smb2_util_close(tree2B, h_client2_file3);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	smb2_deltree(tree1, BASEDIR);

	test_multichannel_free_channels(tree2A, tree2B, tree2C);
	if (tree2D != NULL) {
		TALLOC_FREE(tree2D);
	}
	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

struct test_multichannel_oplock_break_state;

struct test_multichannel_oplock_break_channel {
	struct test_multichannel_oplock_break_state *state;
	size_t idx;
	char name[64];
	struct smb2_tree *tree;
	bool blocked;
	struct timeval break_time;
	double full_duration;
	double relative_duration;
	uint8_t level;
	size_t break_num;
};

struct test_multichannel_oplock_break_state {
	struct torture_context *tctx;
	struct timeval open_req_time;
	struct timeval open_rep_time;
	size_t num_breaks;
	struct timeval last_break_time;
	struct test_multichannel_oplock_break_channel channels[32];
};

static bool test_multichannel_oplock_break_handler(struct smb2_transport *transport,
						   const struct smb2_handle *handle,
						   uint8_t level,
						   void *private_data)
{
	struct test_multichannel_oplock_break_channel *c =
		(struct test_multichannel_oplock_break_channel *)private_data;
	struct test_multichannel_oplock_break_state *state = c->state;

	c->break_time = timeval_current();
	c->full_duration = timeval_elapsed2(&state->open_req_time,
					    &c->break_time);
	c->relative_duration = timeval_elapsed2(&state->last_break_time,
						&c->break_time);
	state->last_break_time = c->break_time;
	c->level = level;
	c->break_num = ++state->num_breaks;

	torture_comment(state->tctx, "Got OPLOCK break %zu on %s after %f ( %f)\n",
			c->break_num, c->name,
			c->relative_duration,
			c->full_duration);

	return torture_oplock_ack_handler(transport, handle, level, c->tree);
}

static bool test_multichannel_oplock_break_test3_windows(struct torture_context *tctx,
							 struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct test_multichannel_oplock_break_state state = {
		.tctx = tctx,
	};
	struct test_multichannel_oplock_break_channel *open2_channel = NULL;
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_create io1;
	struct smb2_create io2;
	bool ret = true;
	const char *fname1 = BASEDIR "\\oplock_break_test3w.dat";
	struct smb2_tree *trees2[32] = { NULL, };
	size_t i;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	bool block_setup = false;
	bool block_ok = false;
	double open_duration;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Oplock break retry: Test3 (Windows behavior)\n");

	torture_reset_break_info(tctx, &break_info);
	break_info.oplock_skip_ack = true;

	transport1->oplock.handler = torture_oplock_ack_handler;
	transport1->oplock.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io2, fname1,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));

	transport2_options = transport1->options;

	ret = test_multichannel_create_channel_array(tctx, host, share, credentials,
						     &transport2_options,
						     ARRAY_SIZE(trees2), trees2);
	torture_assert(tctx, ret, "Could not create channels.\n");

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = trees2[i]->session->transport;

		c->state = &state;
		c->idx = i+1;
		c->tree = trees2[i];
		snprintf(c->name, sizeof(c->name), "trees2_%zu", c->idx);

		t->oplock.handler = test_multichannel_oplock_break_handler;
		t->oplock.private_data = c;
	}

	open2_channel = &state.channels[0];

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via %s\n",
			open2_channel->name);
	status = smb2_create(open2_channel->tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io2.out.durable_open_v2, false);
	CHECK_VAL(io2.out.timeout, io2.in.timeout);
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(break_info.count, 0);

	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = c->tree->session->transport;

		torture_comment(tctx, "Blocking %s\n", c->name);
		block_ok = _test_block_smb2_transport(tctx, t, c->name);
		torture_assert_goto(tctx, block_ok, ret, done, "we could not block tcp transport");
		c->blocked = true;
	}

	/* 1 opens file2 */
	torture_comment(tctx,
			"Client opens fname1 with session 1 with all %zu blocked\n",
			ARRAY_SIZE(trees2));
	smb2_oplock_create_share(&io1, fname1,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	CHECK_VAL(lease_break_info.count, 0);
	state.open_req_time = timeval_current();
	state.last_break_time = state.open_req_time;
	status = smb2_create(tree1, mem_ctx, &io1);
	state.open_rep_time = timeval_current();
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("s"));

	CHECK_VAL(break_info.count, 1);

	open_duration = timeval_elapsed2(&state.open_req_time,
					 &state.open_rep_time);
	torture_comment(tctx, "open_duration: %f\n", open_duration);
	CHECK_VAL_GREATER_THAN(open_duration, 35);

	if (break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected oplock break!!\n");
	} else {
		torture_comment(tctx, "Received %d oplock break(s)!!\n",
				break_info.count);
	}

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		size_t expected_break_num = 0;

		/*
		 * Only the latest channel gets a break notification
		 */
		if (i == (ARRAY_SIZE(state.channels) - 1)) {
			expected_break_num = 1;
		}

		torture_comment(tctx, "Verify %s\n", c->name);
		torture_assert_int_equal(tctx, c->break_num, expected_break_num,
					 "Got oplock break on wrong channel");
		if (expected_break_num != 0) {
			CHECK_VAL(c->level, smb2_util_oplock_level("s"));
		}
	}

done:
	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = NULL;

		if (!c->blocked) {
			continue;
		}

		t = c->tree->session->transport;

		torture_comment(tctx, "Unblocking %s\n", c->name);
		_test_unblock_smb2_transport(tctx, t, c->name);
		c->blocked = false;
	}
	if (block_setup) {
		test_cleanup_blocked_transports(tctx);
	}

	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	if (trees2[0] != NULL) {
		smb2_util_close(trees2[0], h_client2_file1);
	}

	if (h != NULL) {
		smb2_util_close(tree1, *h);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_deltree(tree1, BASEDIR);

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		if (trees2 == NULL || trees2[i] == NULL) {
			continue;
		}
		TALLOC_FREE(trees2[i]);
	}
	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_multichannel_oplock_break_test3_specification(struct torture_context *tctx,
							       struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct test_multichannel_oplock_break_state state = {
		.tctx = tctx,
	};
	struct test_multichannel_oplock_break_channel *open2_channel = NULL;
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_create io1;
	struct smb2_create io2;
	bool ret = true;
	const char *fname1 = BASEDIR "\\oplock_break_test3s.dat";
	struct smb2_tree *trees2[32] = { NULL, };
	size_t i;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	bool block_setup = false;
	bool block_ok = false;
	double open_duration;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Oplock break retry: Test3 (Specification behavior)\n");

	torture_reset_break_info(tctx, &break_info);
	break_info.oplock_skip_ack = true;

	transport1->oplock.handler = torture_oplock_ack_handler;
	transport1->oplock.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	CHECK_VAL(break_info.count, 0);

	smb2_oplock_create_share(&io2, fname1,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));

	transport2_options = transport1->options;

	ret = test_multichannel_create_channel_array(tctx, host, share, credentials,
						     &transport2_options,
						     ARRAY_SIZE(trees2), trees2);
	torture_assert(tctx, ret, "Could not create channels.\n");

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = trees2[i]->session->transport;

		c->state = &state;
		c->idx = i+1;
		c->tree = trees2[i];
		snprintf(c->name, sizeof(c->name), "trees2_%zu", c->idx);

		t->oplock.handler = test_multichannel_oplock_break_handler;
		t->oplock.private_data = c;
	}

	open2_channel = &state.channels[0];

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via %s\n",
			open2_channel->name);
	status = smb2_create(open2_channel->tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io2.out.durable_open_v2, false);
	CHECK_VAL(io2.out.timeout, io2.in.timeout);
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(break_info.count, 0);

	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = c->tree->session->transport;

		torture_comment(tctx, "Blocking %s\n", c->name);
		block_ok = _test_block_smb2_transport(tctx, t, c->name);
		torture_assert_goto(tctx, block_ok, ret, done, "we could not block tcp transport");
		c->blocked = true;
	}

	/* 1 opens file2 */
	torture_comment(tctx,
			"Client opens fname1 with session 1 with all %zu blocked\n",
			ARRAY_SIZE(trees2));
	smb2_oplock_create_share(&io1, fname1,
			smb2_util_share_access("RWD"),
			smb2_util_oplock_level("b"));
	CHECK_VAL(lease_break_info.count, 0);
	state.open_req_time = timeval_current();
	state.last_break_time = state.open_req_time;
	status = smb2_create(tree1, mem_ctx, &io1);
	state.open_rep_time = timeval_current();
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;

	CHECK_VAL_GREATER_THAN(break_info.count, 1);

	open_duration = timeval_elapsed2(&state.open_req_time,
					 &state.open_rep_time);
	torture_comment(tctx, "open_duration: %f\n", open_duration);
	if (break_info.count < ARRAY_SIZE(state.channels)) {
		CHECK_VAL_GREATER_THAN(open_duration, 35);
		CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("s"));
	} else {
		CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));
	}

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		if (break_info.count >= ARRAY_SIZE(state.channels)) {
			break;
		}
		torture_comment(tctx, "Received %d oplock break(s) wait for more!!\n",
				break_info.count);
		torture_wait_for_oplock_break(tctx);
	}

	if (break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected oplock break!!\n");
	} else {
		torture_comment(tctx, "Received %d oplock break(s)!!\n",
				break_info.count);
	}

	if (break_info.count < ARRAY_SIZE(state.channels)) {
		CHECK_VAL_GREATER_THAN(break_info.count, 3);
	} else {
		CHECK_VAL(break_info.count, ARRAY_SIZE(state.channels));
	}

	for (i = 0; i < break_info.count; i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];

		torture_comment(tctx, "Verify %s\n", c->name);
		torture_assert_int_equal(tctx, c->break_num, c->idx,
					 "Got oplock break on wrong channel");
		CHECK_VAL(c->level, smb2_util_oplock_level("s"));
	}

done:
	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_oplock_break_channel *c = &state.channels[i];
		struct smb2_transport *t = NULL;

		if (!c->blocked) {
			continue;
		}

		t = c->tree->session->transport;

		torture_comment(tctx, "Unblocking %s\n", c->name);
		_test_unblock_smb2_transport(tctx, t, c->name);
		c->blocked = false;
	}
	if (block_setup) {
		test_cleanup_blocked_transports(tctx);
	}

	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	if (trees2[0] != NULL) {
		smb2_util_close(trees2[0], h_client2_file1);
	}

	if (h != NULL) {
		smb2_util_close(tree1, *h);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_deltree(tree1, BASEDIR);

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		if (trees2 == NULL || trees2[i] == NULL) {
			continue;
		}
		TALLOC_FREE(trees2[i]);
	}
	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

static const uint64_t LEASE1F1 = 0xBADC0FFEE0DDF00Dull;
static const uint64_t LEASE1F2 = 0xBADC0FFEE0DDD00Dull;
static const uint64_t LEASE1F3 = 0xDADC0FFEE0DDD00Dull;
static const uint64_t LEASE2F1 = 0xDEADBEEFFEEDBEADull;
static const uint64_t LEASE2F2 = 0xDAD0FFEDD00DF00Dull;
static const uint64_t LEASE2F3 = 0xBAD0FFEDD00DF00Dull;

/*
 * Lease Break Test 1:
 * Test to check if lease breaks are sent by the server as expected.
 *      open file1 in session 2A
 *      open file2 in session 2B
 *      open file3 in session 2C
 *      open file1 in session 1
 *           lease break sent
 *      open file2 in session 1
 *           lease break sent
 *      open file3 in session 1
 *           lease break sent
 */
static bool test_multichannel_lease_break_test1(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client1_file2 = {{0}};
	struct smb2_handle h_client1_file3 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_handle h_client2_file2 = {{0}};
	struct smb2_handle h_client2_file3 = {{0}};
	struct smb2_create io1, io2, io3;
	bool ret = true;
	const char *fname1 = BASEDIR "\\lease_break_test1.dat";
	const char *fname2 = BASEDIR "\\lease_break_test2.dat";
	const char *fname3 = BASEDIR "\\lease_break_test3.dat";
	struct smb2_tree *tree2A = NULL;
	struct smb2_tree *tree2B = NULL;
	struct smb2_tree *tree2C = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_lease ls3;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Lease break retry: Test1\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);

	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	CHECK_VAL(lease_break_info.count, 0);

	smb2_lease_create(&io1, &ls1, false, fname1, LEASE2F1,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io1);

	smb2_lease_create(&io2, &ls2, false, fname2, LEASE2F2,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io2);

	smb2_lease_create(&io3, &ls3, false, fname3, LEASE2F3,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io3);

	transport2_options = transport1->options;

	ret = test_multichannel_create_channels(tctx, host, share,
						  credentials,
						  &transport2_options,
						  &tree2A, &tree2B, &tree2C);
	torture_assert(tctx, ret, "Could not create channels.\n");

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via session 2A\n");
	status = smb2_create(tree2A, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RHW", true, LEASE2F1, 0);
	CHECK_VAL(lease_break_info.count, 0);

	/* 2b opens file2 */
	torture_comment(tctx, "client2 opens fname2 via session 2B\n");
	status = smb2_create(tree2B, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RHW", true, LEASE2F2, 0);
	CHECK_VAL(lease_break_info.count, 0);

	/* 2c opens file3 */
	torture_comment(tctx, "client2 opens fname3 via session 2C\n");
	smb2_lease_create(&io3, &ls3, false, fname3, LEASE2F3,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree2C, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RHW", true, LEASE2F3, 0);
	CHECK_VAL(lease_break_info.count, 0);

	/* 1 opens file1 - lease break? */
	torture_comment(tctx, "client1 opens fname1 via session 1\n");
	smb2_lease_create(&io1, &ls1, false, fname1, LEASE1F1,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1F1, 0);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F1);
	CHECK_VAL(lease_break_info.count, 1);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* 1 opens file2 - lease break? */
	torture_comment(tctx, "client1 opens fname2 via session 1\n");
	smb2_lease_create(&io2, &ls2, false, fname2, LEASE1F2,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE1F2, 0);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F2);
	CHECK_VAL(lease_break_info.count, 1);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* 1 opens file3 - lease break? */
	torture_comment(tctx, "client1 opens fname3 via session 1\n");
	smb2_lease_create(&io3, &ls3, false, fname3, LEASE1F3,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RH", true, LEASE1F3, 0);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F3);
	CHECK_VAL(lease_break_info.count, 1);

	/* cleanup everything */
	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);
	smb2_util_close(tree2A, h_client2_file1);
	smb2_util_close(tree2A, h_client2_file2);
	smb2_util_close(tree2A, h_client2_file3);

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	CHECK_VAL(lease_break_info.count, 0);
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

	if (h != NULL) {
		smb2_util_close(tree1, *h);
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

/*
 * Lease Break Test 2:
 * Test for lease break retries being sent by the server.
 *      Connect 2A, 2B
 *      open file1 in session 2A
 *      open file2 in session 2B
 *      block 2A
 *      open file2 in session 1
 *           lease break retry reaches the client?
 *      Connect 2C
 *      open file3 in session 2C
 *      unblock 2A
 *      open file1 in session 1
 *           lease break reaches the client?
 *      open file3 in session 1
 *           lease break reached the client?
 *      Cleanup
 *           On deletion by 1, lease breaks sent for file1, file2 and file3
 *           on 2B
 *           This changes RH lease to R for Session 2.
 *           (This has been disabled while we add support for sending lease
 *            break for handle leases.)
 */
static bool test_multichannel_lease_break_test2(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client1_file2 = {{0}};
	struct smb2_handle h_client1_file3 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_handle h_client2_file2 = {{0}};
	struct smb2_handle h_client2_file3 = {{0}};
	struct smb2_create io1, io2, io3;
	bool ret = true;
	const char *fname1 = BASEDIR "\\lease_break_test1.dat";
	const char *fname2 = BASEDIR "\\lease_break_test2.dat";
	const char *fname3 = BASEDIR "\\lease_break_test3.dat";
	struct smb2_tree *tree2A = NULL;
	struct smb2_tree *tree2B = NULL;
	struct smb2_tree *tree2C = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2A = NULL;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_lease ls3;
	bool block_setup = false;
	bool block_ok = false;
	bool unblock_ok = false;


	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Lease break retry: Test2\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);

	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);
	smb2_util_unlink(tree1, fname3);
	CHECK_VAL(lease_break_info.count, 0);

	smb2_lease_create(&io1, &ls1, false, fname1, LEASE2F1,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io1);

	smb2_lease_create(&io2, &ls2, false, fname2, LEASE2F2,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io2);

	smb2_lease_create(&io3, &ls3, false, fname3, LEASE2F3,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io3);

	transport2_options = transport1->options;

	ret = test_multichannel_create_channels(tctx, host, share,
						  credentials,
						  &transport2_options,
						  &tree2A, &tree2B, NULL);
	torture_assert(tctx, ret, "Could not create channels.\n");
	transport2A = tree2A->session->transport;

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via session 2A\n");
	smb2_lease_create(&io1, &ls1, false, fname1, LEASE2F1,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree2A, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RHW", true, LEASE2F1, 0);
	CHECK_VAL(io1.out.durable_open_v2, false); //true);
	CHECK_VAL(io1.out.timeout, io1.in.timeout);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(lease_break_info.count, 0);

	/* 2b opens file2 */
	torture_comment(tctx, "client2 opens fname2 via session 2B\n");
	smb2_lease_create(&io2, &ls2, false, fname2, LEASE2F2,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree2B, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RHW", true, LEASE2F2, 0);
	CHECK_VAL(io2.out.durable_open_v2, false); //true);
	CHECK_VAL(io2.out.timeout, io2.in.timeout);
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(lease_break_info.count, 0);

	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");

	torture_comment(tctx, "Blocking 2A\n");
	/* Block 2A */
	block_ok = test_block_smb2_transport(tctx, transport2A);
	torture_assert(tctx, block_ok, "we could not block tcp transport");

	torture_wait_for_lease_break(tctx);
	CHECK_VAL(lease_break_info.count, 0);

	/* 1 opens file2 */
	torture_comment(tctx,
			"Client opens fname2 with session1 with 2A blocked\n");
	smb2_lease_create(&io2, &ls2, false, fname2, LEASE1F2,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE1F2, 0);
	CHECK_VAL(io2.out.durable_open_v2, false);
	CHECK_VAL(io2.out.timeout, 0);
	CHECK_VAL(io2.out.durable_open, false);

	if (lease_break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected lease break!!\n");
	} else {
		torture_comment(tctx, "Received %d lease break(s)!!\n",
				lease_break_info.count);
	}

	/*
	 * We got breaks on both channels
	 * (one failed on the blocked connection)
	 */
	CHECK_VAL(lease_break_info.count, 2);
	lease_break_info.count -= 1;
	CHECK_VAL(lease_break_info.failures, 1);
	lease_break_info.failures -= 1;
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F2);
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Connect 2C */
	torture_comment(tctx, "Connecting session 2C\n");
	talloc_free(tree2C);
	tree2C = test_multichannel_create_channel(tctx, host, share,
				credentials, &transport2_options, tree2A);
	if (!tree2C) {
		goto done;
	}

	/* 2c opens file3 */
	torture_comment(tctx, "client2 opens fname3 via session 2C\n");
	smb2_lease_create(&io3, &ls3, false, fname3, LEASE2F3,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree2C, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RHW", true, LEASE2F3, 0);
	CHECK_VAL(io3.out.durable_open_v2, false);
	CHECK_VAL(io3.out.timeout, io2.in.timeout);
	CHECK_VAL(io3.out.durable_open, false);
	CHECK_VAL(lease_break_info.count, 0);

	/* Unblock 2A */
	torture_comment(tctx, "Unblocking 2A\n");
	unblock_ok = test_unblock_smb2_transport(tctx, transport2A);
	torture_assert(tctx, unblock_ok, "we could not unblock tcp transport");

	/* 1 opens file1 */
	torture_comment(tctx, "Client opens fname1 with session 1\n");
	smb2_lease_create(&io1, &ls1, false, fname1, LEASE1F1,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1F1, 0);

	if (lease_break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected lease break!!\n");
	} else {
		torture_comment(tctx,
				"Received %d lease break(s)!!\n",
				lease_break_info.count);
	}
	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F1);
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/*1 opens file3 */
	torture_comment(tctx, "client opens fname3 via session 1\n");

	smb2_lease_create(&io3, &ls3, false, fname3, LEASE1F3,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RH", true, LEASE1F3, 0);

	if (lease_break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected lease break!!\n");
	} else {
		torture_comment(tctx,
				"Received %d lease break(s)!!\n",
				lease_break_info.count);
	}
	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F3);
	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);

	/*
	 * Session 2 still has RW lease on file 1. Deletion of this file by 1
	 *  leads to a lease break call to session 2 file1
	 */
	smb2_util_unlink(tree1, fname1);
	/*
	 * Bug - Samba does not revoke Handle lease on unlink
	 * CHECK_BREAK_INFO("RH", "R", LEASE2F1);
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/*
	 * Session 2 still has RW lease on file 2. Deletion of this file by 1
	 *  leads to a lease break call to session 2 file2
	 */
	smb2_util_unlink(tree1, fname2);
	/*
	 * Bug - Samba does not revoke Handle lease on unlink
	 * CHECK_BREAK_INFO("RH", "R", LEASE2F2);
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/*
	 * Session 2 still has RW lease on file 3. Deletion of this file by 1
	 *  leads to a lease break call to session 2 file3
	 */
	smb2_util_unlink(tree1, fname3);
	/*
	 * Bug - Samba does not revoke Handle lease on unlink
	 * CHECK_BREAK_INFO("RH", "R", LEASE2F3);
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_util_close(tree2C, h_client2_file1);
	smb2_util_close(tree2C, h_client2_file2);
	smb2_util_close(tree2C, h_client2_file3);

	test_multichannel_free_channels(tree2A, tree2B, tree2C);
	tree2A = tree2B = tree2C = NULL;

done:
	if (block_ok && !unblock_ok) {
		test_unblock_smb2_transport(tctx, transport2A);
	}
	if (block_setup) {
		test_cleanup_blocked_transports(tctx);
	}

	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	smb2_util_close(tree1, h_client1_file2);
	smb2_util_close(tree1, h_client1_file3);
	if (tree2A != NULL) {
		smb2_util_close(tree2A, h_client2_file1);
		smb2_util_close(tree2A, h_client2_file2);
		smb2_util_close(tree2A, h_client2_file3);
	}

	if (h != NULL) {
		smb2_util_close(tree1, *h);
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

/*
 * Test 3: Check to see how the server behaves if lease break
 *      response is sent over a different channel to one over which
 *      the break is received.
 *      Connect 2A, 2B
 *      open file1 in session 2A
 *      open file1 in session 1
 *           Lease break sent to 2A
 *           2B sends back lease break reply.
 *      session 1 allowed to open file
 */
static bool test_multichannel_lease_break_test3(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_create io1;
	bool ret = true;
	const char *fname1 = BASEDIR "\\lease_break_test1.dat";
	struct smb2_tree *tree2A = NULL;
	struct smb2_tree *tree2B = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2A = NULL;
	struct smbcli_options transport2_options;
	uint16_t local_port = 0;
	struct smb2_lease ls1;
	struct tevent_timer *te = NULL;
	struct timeval ne;
	bool timesup = false;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Lease break retry: Test3\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);

	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	CHECK_VAL(lease_break_info.count, 0);

	smb2_lease_create(&io1, &ls1, false, fname1, LEASE2F1,
			  smb2_util_lease_state("RHW"));
	test_multichannel_init_smb_create(&io1);

	transport2_options = transport1->options;

	ret = test_multichannel_create_channels(tctx, host, share,
						credentials,
						&transport2_options,
						&tree2A, &tree2B, NULL);
	torture_assert(tctx, ret, "Could not create channels.\n");
	transport2A = tree2A->session->transport;
	transport2A->lease.private_data = tree2B;

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via session 2A\n");
	smb2_lease_create(&io1, &ls1, false, fname1, LEASE2F1,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree2A, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RHW", true, LEASE2F1, 0);
	CHECK_VAL(io1.out.durable_open_v2, false); //true);
	CHECK_VAL(io1.out.timeout, io1.in.timeout);
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(lease_break_info.count, 0);

	/* Set a timeout for 5 seconds for session 1 to open file1 */
	ne = tevent_timeval_current_ofs(0, 5000000);
	te = tevent_add_timer(tctx->ev, tmp_ctx, ne, timeout_cb, &timesup);
	if (te == NULL) {
		torture_comment(tctx, "Failed to add timer.");
		goto done;
	}

	/* 1 opens file2 */
	torture_comment(tctx, "Client opens fname1 with session 1\n");
	smb2_lease_create(&io1, &ls1, false, fname1, LEASE1F1,
			  smb2_util_lease_state("RHW"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1F1, 0);
	CHECK_VAL(io1.out.durable_open_v2, false);
	CHECK_VAL(io1.out.timeout, 0);
	CHECK_VAL(io1.out.durable_open, false);

	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RHW", "RH", LEASE2F1);

	/*
	 * Check if timeout handler was fired. This would indicate
	 * that the server didn't receive a reply for the oplock break
	 * from the client and the server let session 1 open the file
	 * only after the oplock break timeout.
	 */
	CHECK_VAL(timesup, false);

done:
	smb2_util_close(tree1, h_client1_file1);
	if (tree2A != NULL) {
		smb2_util_close(tree2A, h_client2_file1);
	}

	if (h != NULL) {
		smb2_util_close(tree1, *h);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_deltree(tree1, BASEDIR);

	test_multichannel_free_channels(tree2A, tree2B, NULL);
	talloc_free(tree1);
	talloc_free(mem_ctx);

	return ret;
}

/*
 * Test limits of channels
 */
static bool test_multichannel_num_channels(struct torture_context *tctx,
					   struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	bool ret = true;
	struct smb2_tree **tree2 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport **transport2 = NULL;
	struct smbcli_options transport2_options;
	struct smb2_session **session2 = NULL;
	uint32_t server_capabilities;
	int i;
	int max_channels = 33; /* 32 is the W2K12R2 and W2K16 limit */

	if (smbXcli_conn_protocol(transport1->conn) < PROTOCOL_SMB3_00) {
		torture_fail(tctx,
			     "SMB 3.X Dialect family required for Multichannel"
			     " tests\n");
	}

	server_capabilities = smb2cli_conn_server_capabilities(
					tree1->session->transport->conn);
	if (!(server_capabilities & SMB2_CAP_MULTI_CHANNEL)) {
		torture_fail(tctx,
			     "Server does not support multichannel.");
	}

	torture_comment(tctx, "Testing max. number of channels\n");

	transport2_options = transport1->options;
	transport2_options.client_guid = GUID_random();

	tree2		= talloc_zero_array(mem_ctx, struct smb2_tree *,
					    max_channels);
	transport2	= talloc_zero_array(mem_ctx, struct smb2_transport *,
					    max_channels);
	session2	= talloc_zero_array(mem_ctx, struct smb2_session *,
					    max_channels);
	if (tree2 == NULL || transport2 == NULL || session2 == NULL) {
		torture_fail(tctx, "out of memory");
	}

	for (i = 0; i < max_channels; i++) {

		NTSTATUS expected_status;

		torture_assert_ntstatus_ok_goto(tctx,
			smb2_connect(tctx,
				host,
				lpcfg_smb_ports(tctx->lp_ctx),
				share,
				lpcfg_resolve_context(tctx->lp_ctx),
				credentials,
				&tree2[i],
				tctx->ev,
				&transport2_options,
				lpcfg_socket_options(tctx->lp_ctx),
				lpcfg_gensec_settings(tctx, tctx->lp_ctx)
				),
			ret, done, "smb2_connect failed");

		transport2[i] = tree2[i]->session->transport;

		if (i == 0) {
			/*
			 * done for the 1st channel
			 *
			 * For all remaining channels we do the
			 * session setup on our own.
			 */
			transport2_options.only_negprot = true;
			continue;
		}

		/*
		 * Now bind the session2[i] to the transport2
		 */
		session2[i] = smb2_session_channel(transport2[i],
						   lpcfg_gensec_settings(tctx,
								 tctx->lp_ctx),
						   tree2[0],
						   tree2[0]->session);

		torture_assert(tctx, session2[i] != NULL,
			       "smb2_session_channel failed");

		torture_comment(tctx, "established transport2 [#%d]\n", i);

		if (i >= 32) {
			expected_status = NT_STATUS_INSUFFICIENT_RESOURCES;
		} else {
			expected_status = NT_STATUS_OK;
		}

		torture_assert_ntstatus_equal_goto(tctx,
			smb2_session_setup_spnego(session2[i],
				popt_get_cmdline_credentials(),
				0 /* previous_session_id */),
			expected_status,
			ret, done,
			talloc_asprintf(tctx, "failed to establish session "
					      "setup for channel #%d", i));

		torture_comment(tctx, "bound session2 [#%d] to session2 [0]\n",
				i);
	}

 done:
	talloc_free(mem_ctx);

	return ret;
}

struct test_multichannel_lease_break_state;

struct test_multichannel_lease_break_channel {
	struct test_multichannel_lease_break_state *state;
	size_t idx;
	char name[64];
	struct smb2_tree *tree;
	bool blocked;
	struct timeval break_time;
	double full_duration;
	double relative_duration;
	struct smb2_lease_break lb;
	size_t break_num;
};

struct test_multichannel_lease_break_state {
	struct torture_context *tctx;
	struct timeval open_req_time;
	struct timeval open_rep_time;
	size_t num_breaks;
	struct timeval last_break_time;
	struct test_multichannel_lease_break_channel channels[32];
};

static bool test_multichannel_lease_break_handler(struct smb2_transport *transport,
						  const struct smb2_lease_break *lb,
						  void *private_data)
{
	struct test_multichannel_lease_break_channel *c =
		(struct test_multichannel_lease_break_channel *)private_data;
	struct test_multichannel_lease_break_state *state = c->state;

	c->break_time = timeval_current();
	c->full_duration = timeval_elapsed2(&state->open_req_time,
					    &c->break_time);
	c->relative_duration = timeval_elapsed2(&state->last_break_time,
						&c->break_time);
	state->last_break_time = c->break_time;
	c->lb = *lb;
	c->break_num = ++state->num_breaks;

	torture_comment(state->tctx, "Got LEASE break epoch[0x%x] %zu on %s after %f ( %f)\n",
			c->lb.new_epoch, c->break_num, c->name,
			c->relative_duration,
			c->full_duration);

	return torture_lease_handler(transport, lb, c->tree);
}

static bool test_multichannel_lease_break_test4(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct test_multichannel_lease_break_state state = {
		.tctx = tctx,
	};
	struct test_multichannel_lease_break_channel *open2_channel = NULL;
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_handle h_client1_file1 = {{0}};
	struct smb2_handle h_client2_file1 = {{0}};
	struct smb2_create io1;
	struct smb2_create io2;
	bool ret = true;
	const char *fname1 = BASEDIR "\\lease_break_test4.dat";
	struct smb2_tree *trees2[32] = { NULL, };
	size_t i;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options transport2_options;
	struct smb2_session *session1 = tree1->session;
	uint16_t local_port = 0;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	bool block_setup = false;
	bool block_ok = false;
	double open_duration;

	if (!test_multichannel_initial_checks(tctx, tree1)) {
		return true;
	}

	torture_comment(tctx, "Lease break retry: Test4\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	torture_comment(tctx, "transport1  [%p]\n", transport1);
	local_port = torture_get_local_port_from_transport(transport1);
	torture_comment(tctx, "transport1 uses tcp port: %d\n", local_port);

	status = torture_smb2_testdir(tree1, BASEDIR, &_h);
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree1, _h);
	smb2_util_unlink(tree1, fname1);
	CHECK_VAL(lease_break_info.count, 0);

	smb2_lease_v2_create(&io2, &ls2, false, fname1,
			     LEASE2F1, NULL,
			     smb2_util_lease_state("RHW"),
			     0x20);

	transport2_options = transport1->options;

	ret = test_multichannel_create_channel_array(tctx, host, share, credentials,
						     &transport2_options,
						     ARRAY_SIZE(trees2), trees2);
	torture_assert(tctx, ret, "Could not create channels.\n");

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		struct test_multichannel_lease_break_channel *c = &state.channels[i];
		struct smb2_transport *t = trees2[i]->session->transport;

		c->state = &state;
		c->idx = i+1;
		c->tree = trees2[i];
		snprintf(c->name, sizeof(c->name), "trees2_%zu", c->idx);

		t->lease.handler = test_multichannel_lease_break_handler;
		t->lease.private_data = c;
	}

	open2_channel = &state.channels[0];

	/* 2a opens file1 */
	torture_comment(tctx, "client2 opens fname1 via %s\n",
			open2_channel->name);
	status = smb2_create(open2_channel->tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client2_file1 = io2.out.file.handle;
	CHECK_CREATED(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io2, "RHW", true, LEASE2F1, 0, 0, 0x21);
	CHECK_VAL(io2.out.durable_open_v2, false);
	CHECK_VAL(io2.out.timeout, io2.in.timeout);
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(lease_break_info.count, 0);

	block_setup = test_setup_blocked_transports(tctx);
	torture_assert(tctx, block_setup, "test_setup_blocked_transports");

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_lease_break_channel *c = &state.channels[i];
		struct smb2_transport *t = c->tree->session->transport;

		torture_comment(tctx, "Blocking %s\n", c->name);
		block_ok = _test_block_smb2_transport(tctx, t, c->name);
		torture_assert_goto(tctx, block_ok, ret, done, "we could not block tcp transport");
		c->blocked = true;
	}

	/* 1 opens file2 */
	torture_comment(tctx,
			"Client opens fname1 with session 1 with all %zu blocked\n",
			ARRAY_SIZE(trees2));
	smb2_lease_v2_create(&io1, &ls1, false, fname1,
			     LEASE1F1, NULL,
			     smb2_util_lease_state("RHW"),
			     0x10);
	CHECK_VAL(lease_break_info.count, 0);
	state.open_req_time = timeval_current();
	state.last_break_time = state.open_req_time;
	status = smb2_create(tree1, mem_ctx, &io1);
	state.open_rep_time = timeval_current();
	CHECK_STATUS(status, NT_STATUS_OK);
	h_client1_file1 = io1.out.file.handle;

	CHECK_VAL_GREATER_THAN(lease_break_info.count, 1);

	open_duration = timeval_elapsed2(&state.open_req_time,
					 &state.open_rep_time);
	torture_comment(tctx, "open_duration: %f\n", open_duration);
	if (lease_break_info.count < ARRAY_SIZE(state.channels)) {
		CHECK_VAL_GREATER_THAN(open_duration, 35);
		CHECK_LEASE_V2(&io1, "RH", true, LEASE1F1, 0, 0, 0x11);
	} else {
		CHECK_LEASE_V2(&io1, "RWH", true, LEASE1F1, 0, 0, 0x11);
	}

	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		if (lease_break_info.count >= ARRAY_SIZE(state.channels)) {
			break;
		}
		torture_comment(tctx, "Received %d lease break(s) wait for more!!\n",
				lease_break_info.count);
		torture_wait_for_lease_break(tctx);
	}

	if (lease_break_info.count == 0) {
		torture_comment(tctx,
				"Did not receive expected lease break!!\n");
	} else {
		torture_comment(tctx, "Received %d lease break(s)!!\n",
				lease_break_info.count);
	}

	if (lease_break_info.count < ARRAY_SIZE(state.channels)) {
		CHECK_VAL_GREATER_THAN(lease_break_info.count, 3);
	} else {
		CHECK_VAL(lease_break_info.count, ARRAY_SIZE(state.channels));
	}

	for (i = 0; i < lease_break_info.count; i++) {
		struct test_multichannel_lease_break_channel *c = &state.channels[i];

		torture_comment(tctx, "Verify %s\n", c->name);
		torture_assert_int_equal(tctx, c->break_num, c->idx,
					 "Got lease break in wrong order");
		CHECK_LEASE_BREAK_V2(c->lb, LEASE2F1, "RWH", "RH",
				     SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED,
				     0x22);
	}

done:
	for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
		struct test_multichannel_lease_break_channel *c = &state.channels[i];
		struct smb2_transport *t = NULL;

		if (!c->blocked) {
			continue;
		}

		t = c->tree->session->transport;

		torture_comment(tctx, "Unblocking %s\n", c->name);
		_test_unblock_smb2_transport(tctx, t, c->name);
		c->blocked = false;
	}
	if (block_setup) {
		test_cleanup_blocked_transports(tctx);
	}

	tree1->session = session1;

	smb2_util_close(tree1, h_client1_file1);
	if (trees2[0] != NULL) {
		smb2_util_close(trees2[0], h_client2_file1);
	}

	if (h != NULL) {
		smb2_util_close(tree1, *h);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_deltree(tree1, BASEDIR);

	for (i = 0; i < ARRAY_SIZE(trees2); i++) {
		if (trees2 == NULL || trees2[i] == NULL) {
			continue;
		}
		TALLOC_FREE(trees2[i]);
	}
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
	struct torture_suite *suite_leases = torture_suite_create(ctx,
								  "leases");

	torture_suite_add_suite(suite, suite_generic);
	torture_suite_add_suite(suite, suite_oplocks);
	torture_suite_add_suite(suite, suite_leases);

	torture_suite_add_1smb2_test(suite_generic, "interface_info",
				     test_multichannel_interface_info);
	torture_suite_add_1smb2_test(suite_generic, "num_channels",
				     test_multichannel_num_channels);
	torture_suite_add_1smb2_test(suite_oplocks, "test1",
				     test_multichannel_oplock_break_test1);
	torture_suite_add_1smb2_test(suite_oplocks, "test2",
				     test_multichannel_oplock_break_test2);
	torture_suite_add_1smb2_test(suite_oplocks, "test3_windows",
				     test_multichannel_oplock_break_test3_windows);
	torture_suite_add_1smb2_test(suite_oplocks, "test3_specification",
				     test_multichannel_oplock_break_test3_specification);
	torture_suite_add_1smb2_test(suite_leases, "test1",
				     test_multichannel_lease_break_test1);
	torture_suite_add_1smb2_test(suite_leases, "test2",
				     test_multichannel_lease_break_test2);
	torture_suite_add_1smb2_test(suite_leases, "test3",
				     test_multichannel_lease_break_test3);
	torture_suite_add_1smb2_test(suite_leases, "test4",
				     test_multichannel_lease_break_test4);

	suite->description = talloc_strdup(suite, "SMB2 Multichannel tests");

	return suite;
}
