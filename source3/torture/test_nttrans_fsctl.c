/*
   Unix SMB/CIFS implementation.
   Basic test for NTTRANS FSCTL requests (copied from NTTRANS CREATE)
   Copyright (C) Richard Sharpe 2011
   Copyright (C) Volker Lendecke 2011

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
#include "torture/proto.h"
#include "libsmb/libsmb.h"
#include "libcli/security/security.h"

bool run_nttrans_fsctl(int dummy)
{
	struct cli_state *cli = NULL;
	NTSTATUS status;
	bool ret = false;
	const char *fname = "fsctltest";
	uint16_t fnum;
	uint16_t setup[4];
	uint8_t *object_data = NULL;
	uint8_t *ranges = NULL;
	uint8_t range_data[16];
	uint8_t *param_data = NULL;
	uint8_t data[1] = { 0x1 };
	uint32_t rdata_size;
	uint32_t rparam_size;

	printf("Starting NTTRANS_FSCTL\n");

	if (!torture_open_connection(&cli, 0)) {
		printf("torture_open_connection failed\n");
		goto fail;
	}

	status = cli_nttrans_create(
		cli, fname, 0, FILE_READ_DATA|FILE_WRITE_DATA|DELETE_ACCESS|
		READ_CONTROL_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE| FILE_SHARE_DELETE,
		FILE_CREATE, 0, 0, NULL, NULL, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_nttrans_create returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = cli_nt_delete_on_close(cli, fnum, true);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_nt_delete_on_close returned %s\n",
			  nt_errstr(status));
		goto fail;
	}

	/* Fill in for FSCTL_SET_SPARSE and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_SET_SPARSE); /* returns value */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   data, 1, 1,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   NULL, 0, NULL); /* rdata, ... */
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_trans of FSCTL_SET_SPARSE returned %s instead of NT_STATUS_OK\n",
			nt_errstr(status));
		goto fail;
	}

	printf("FSCTL_SET_SPARSE returned correct status \n");

	/* Fill in for FSCTL_CREATE_OR_GET_OBJECT_ID and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_CREATE_OR_GET_OBJECT_ID); /* returns value */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   NULL, 0, 64,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   &param_data, 0, &rparam_size, /* rparam, min_rparam, num_rparam */
			   &object_data, 0, &rdata_size); /* rdata, ... */
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_trans of FSCTL_CREATE_OR_GET_OBJECT_ID returned %s instead of NT_STATUS_OK\n",
			nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(object_data);
	TALLOC_FREE(param_data);

	printf("FSCTL_CREATE_OR_GET_OBJECT_ID returned correct status \n");

	/* Fill in for FSCTL_GET_REPARSE_POINT and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_GET_REPARSE_POINT); /* returns NOT A REPARSE POINT */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   NULL, 0, 0,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   NULL, 0, NULL); /* rdata, ... */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_REPARSE_POINT)) {
		d_fprintf(stderr, "cli_trans of FSCTL_GET_REPARSE_POINT returned %s instead of NT_STATUS_NOT_A_REPARSE_POINT\n",
			nt_errstr(status));
		goto fail;
	}

	printf("FSCTL_GET_REPARSE_POINT returned correct status \n");

	/* Fill in for FSCTL_SET_REPARSE_POINT and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_SET_REPARSE_POINT); /* returns NOT A REPARSE POINT */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   NULL, 0, 0,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   NULL, 0, NULL); /* rdata, ... */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_REPARSE_POINT)) {
		d_fprintf(stderr, "cli_trans of FSCTL_SET_REPARSE_POINT returned %s instead of NT_STATUS_NOT_A_REPARSE_POINT\n",
			nt_errstr(status));
		goto fail;
	}

	printf("FSCTL_SET_REPARSE_POINT returned correct status \n");

	/* 
 	 * Fill in for FSCTL_GET_SHADOW_COPY_DATA and call cli_trans ... what
 	 * we do is send an invalid data length to provoke an INVALID PARAMETER
 	 * response.
 	 */
	SIVAL(setup, 0, FSCTL_GET_SHADOW_COPY_DATA); /* Should return IVN VAL */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	memset(range_data, 0, sizeof(range_data));  /* 0 and 0 */

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   NULL, 0, 8,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   &ranges, 0, &rdata_size); /* rdata, ... */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		d_fprintf(stderr, "cli_trans of FSCTL_QUERY_ALLOCATED_RANGES returned %s instead of NT_STATUS_INVALID_PARAMETER\n",
			nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(ranges);

	printf("FSCTL_GET_SHADOW_COPY_DATA returned correct status \n");
	/* 
	 * Fill in for FSCTL_FIND_FILES_BY and call cli_trans ... here we are
	 * only probing for its existence by provoking an INVALID PARAM
	 * response with a short and invalid SID in range_data
	 */
	SIVAL(setup, 0, FSCTL_FIND_FILES_BY_SID); /* Should return 16 bytes */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	memset(range_data, 0, sizeof(range_data));  /* 0 and 0 */

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   range_data, 4, 16,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   &ranges, 0, &rdata_size); /* rdata, ... */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		d_fprintf(stderr, "cli_trans of FSCTL_QUERY_ALLOCATED_RANGES returned %s instead of NT_STATUS_INVALID_PARAMETER\n",
			nt_errstr(status));
		goto fail;
	}

	printf("FSCTL_FIND_FILES_BY_SID returned correct status \n");

	/* Fill in for FSCTL_QUERY_ALLOCATED_RANGES and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_QUERY_ALLOCATED_RANGES); /* Should return 16 bytes */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	memset(range_data, 0, sizeof(range_data));  /* 0 and 0 */

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   range_data, 16, 16,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   &ranges, 0, &rdata_size); /* rdata, ... */
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_trans of FSCTL_QUERY_ALLOCATED_RANGES returned %s instead of NT_STATUS_OK\n",
			nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(ranges);

	printf("FSCTL_QUERY_ALLOCATED_RANGES returned correct status \n");

	/* Fill in for FSCTL_IS_VOLUME_DIRTY and call cli_trans ... */
	SIVAL(setup, 0, FSCTL_IS_VOLUME_DIRTY); /* Should return INVAL PARAM */
	SSVAL(setup, 4, fnum);
	SCVAL(setup, 6, 0x1);   /* It is an fsctl */
	SCVAL(setup, 7, 0x0);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, fnum,
			   NT_TRANSACT_IOCTL, 0,
			   setup, 4, 4,
			   NULL, 0, 0,    /* param, param_num, max_param */
			   NULL, 0, 0,    /* data, data_len, max_data */
			   NULL,          /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup, min_rsetup, num_rsetup */
			   NULL, 0, NULL, /* rparam, min_rparam, num_rparam */
			   NULL, 0, NULL); /* rdata, ... */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		d_fprintf(stderr, "cli_trans of FSCTL_IS_VOLUME_DIRTY returned %s instead of NT_STATUS_INVALID_PARAMETER\n",
			nt_errstr(status));
		goto fail;
	}

	printf("FSCTL_IS_VOLUME_DIRTY returned correct status \n");

	ret = true;
fail:
	if (cli != NULL) {
		torture_close_connection(cli);
	}
	return ret;
}
