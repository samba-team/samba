/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Günther Deschner 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpcclient.h"

static WERROR cmd_ntsvcs_get_version(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc,
				     const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	uint16_t version;

	status = rpccli_PNP_GetVersion(cli, mem_ctx,
				       &version, &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("version: %d\n", version);
	}

	return werr;
}

static WERROR cmd_ntsvcs_validate_dev_inst(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	const char *devicepath = NULL;
	uint32_t flags = 0;

	if (argc < 2 || argc > 3) {
		printf("usage: %s [devicepath] <flags>\n", argv[0]);
		return WERR_OK;
	}

	devicepath = argv[1];

	if (argc >= 3) {
		flags = atoi(argv[2]);
	}

	status = rpccli_PNP_ValidateDeviceInstance(cli, mem_ctx,
						   devicepath,
						   flags,
						   &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return werr;
}

static WERROR cmd_ntsvcs_get_device_list_size(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	const char *devicename = NULL;
	uint32_t flags = 0;
	uint32_t size = 0;

	if (argc < 2 || argc > 4) {
		printf("usage: %s [devicename] <flags>\n", argv[0]);
		return WERR_OK;
	}

	devicename = argv[1];

	if (argc >= 3) {
		flags = atoi(argv[2]);
	}

	status = rpccli_PNP_GetDeviceListSize(cli, mem_ctx,
					      devicename,
					      &size,
					      flags,
					      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("size: %d\n", size);
	}

	return werr;
}

static WERROR cmd_ntsvcs_hw_prof_flags(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	const char *devicepath = NULL;
	uint32_t unk3 = 0;
	uint16_t unk4 = 0;
	const char *unk5 = NULL;
	const char *unk5a = NULL;

	if (argc < 2) {
		printf("usage: %s [devicepath]\n", argv[0]);
		return WERR_OK;
	}

	devicepath = argv[1];

	status = rpccli_PNP_HwProfFlags(cli, mem_ctx,
					0,
					devicepath,
					0,
					&unk3,
					&unk4,
					unk5,
					&unk5a,
					0,
					0,
					&werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return werr;
}

static WERROR cmd_ntsvcs_get_hw_prof_info(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t idx = 0;
	struct PNP_HwProfInfo info;
	uint32_t unknown1 = 0, unknown2 = 0;

	ZERO_STRUCT(info);

	status = rpccli_PNP_GetHwProfInfo(cli, mem_ctx,
					  idx,
					  &info,
					  unknown1,
					  unknown2,
					  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return werr;
}

struct cmd_set ntsvcs_commands[] = {

	{ "NTSVCS" },
	{ "ntsvcs_getversion", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_get_version, PI_NTSVCS, NULL, "Query NTSVCS version", "" },
	{ "ntsvcs_validatedevinst", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_validate_dev_inst, PI_NTSVCS, NULL, "Query NTSVCS device instance", "" },
	{ "ntsvcs_getdevlistsize", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_get_device_list_size, PI_NTSVCS, NULL, "Query NTSVCS get device list", "" },
	{ "ntsvcs_hwprofflags", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_hw_prof_flags, PI_NTSVCS, NULL, "Query NTSVCS HW prof flags", "" },
	{ "ntsvcs_hwprofinfo", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_get_hw_prof_info, PI_NTSVCS, NULL, "Query NTSVCS HW prof info", "" },
	{ NULL }
};
