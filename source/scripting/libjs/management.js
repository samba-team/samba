/*
	backend code for Samba4 management
	Copyright Andrew Tridgell 2005
	Released under the GNU GPL v2 or later
*/


/*
  return a list of current sessions 
*/
function smbsrv_sessions()
{
	var conn = new Object();
	var irpc = irpc_init();
	status = irpc_connect(conn, "smb_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.SMBSRV_INFO_SESSIONS;
	status = irpc.smbsrv_information(conn, io);
	if (status.is_ok != true) {
		return undefined;
	}

	/* gather the results into a single array */
	var i, count=0, ret = new Object();
	for (i=0;i<io.results.length;i++) {
		var sessions = io.results[i].info.sessions.sessions;
		var j;
		for (j=0;j<sessions.length;j++) {
			ret[count] = sessions[j];
			count++;
		}
	}
	ret.length = count;
	return ret;
}

/*
  return a list of current tree connects
*/
function smbsrv_trees()
{
	var conn = new Object();
	var irpc = irpc_init();
	status = irpc_connect(conn, "smb_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.SMBSRV_INFO_TREES;
	status = irpc.smbsrv_information(conn, io);
	if (status.is_ok != true) {
		return undefined;
	}

	/* gather the results into a single array */
	var i, count=0, ret = new Object();
	for (i=0;i<io.results.length;i++) {
		var trees = io.results[i].info.trees.trees;
		var j;
		for (j=0;j<trees.length;j++) {
			ret[count] = trees[j];
			count++;
		}
	}
	ret.length = count;
	return ret;
}

/*
  return nbtd statistics
*/
function nbtd_statistics()
{
	var conn = new Object();
	var irpc = irpc_init();
	status = irpc_connect(conn, "nbt_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.NBTD_INFO_STATISTICS;
	status = irpc.nbtd_information(conn, io);
	if (status.is_ok != true) {
		return undefined;
	}
	return io.results[0].info.stats;
}
