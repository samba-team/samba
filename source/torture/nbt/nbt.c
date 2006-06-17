/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/torture.h"
#include "torture/nbt/proto.h"

NTSTATUS torture_nbt_init(void)
{
	/* nbt tests */
	register_torture_op("NBT-REGISTER", torture_nbt_register);
	register_torture_op("NBT-WINS", torture_nbt_wins);
	register_torture_op("NBT-DGRAM", torture_nbt_dgram);
	register_torture_op("NBT-BROWSE", torture_nbt_browse);
	register_torture_op("NBT-WINSREPLICATION-SIMPLE", torture_nbt_winsreplication_simple);
	register_torture_op("NBT-WINSREPLICATION-REPLICA", torture_nbt_winsreplication_replica);
	register_torture_op("NBT-WINSREPLICATION-OWNED", torture_nbt_winsreplication_owned);
	register_torture_op("BENCH-WINS", torture_bench_wins);
	register_torture_op("BENCH-NBT",     torture_bench_nbt);
	
	return NT_STATUS_OK;
}
