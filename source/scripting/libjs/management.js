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
	assert(status.is_ok == true);

	var io = irpcObj();
	io.input.level = irpc.SMBSRV_INFO_SESSIONS;
	status = irpc.smbsrv_information(conn, io);

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
