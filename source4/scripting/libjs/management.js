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
	var irpc = irpc_init();
	status = irpc.connect("smb_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.SMBSRV_INFO_SESSIONS;
	status = irpc.smbsrv_information(io);
	if (status.is_ok != true) {
		return undefined;
	}

	/* gather the results into a single array */
	var i, count=0, ret = new Array(0);
	for (i=0;i<io.results.length;i++) {
		var sessions = io.results[i].info.sessions.sessions;
		var j;
		for (j=0;j<sessions.length;j++) {
			ret[count] = sessions[j];
			count++;
		}
	}
	return ret;
}

/*
  return a list of current tree connects
*/
function smbsrv_tcons()
{
	var irpc = irpc_init();
	status = irpc.connect("smb_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.SMBSRV_INFO_TCONS;
	status = irpc.smbsrv_information(io);
	if (status.is_ok != true) {
		return undefined;
	}

	/* gather the results into a single array */
	var i, count=0, ret = new Object();
	for (i=0;i<io.results.length;i++) {
		var tcons = io.results[i].info.tcons.tcons;
		var j;
		for (j=0;j<tcons.length;j++) {
			ret[count] = tcons[j];
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
	var irpc = irpc_init();
	status = irpc.connect("nbt_server");
	if (status.is_ok != true) {
		return undefined;
	}

	var io = irpcObj();
	io.input.level = irpc.NBTD_INFO_STATISTICS;
	status = irpc.nbtd_information(io);
	if (status.is_ok != true) {
		return undefined;
	}
	return io.results[0].info.stats;
}

/*
  see if a service is enabled
*/
function service_enabled(name)
{
	var lp = loadparm_init();
	var services = lp.get("server services");
	var i;
	for (i=0;i<services.length;i++) {
		if (services[i] == name) {
			return true;
		}
	}
	return false;
}

/*
  show status of a server
*/
function server_status(name)
{
	var i;
	var io;
	var irpc = irpc_init();

	if (!service_enabled(name)) {
		return "DISABLED";
	}
	
	status = irpc.connect(name + "_server");
	if (status.is_ok != true) {
		return "DOWN";
	}

	var io = irpcObj();
	status = irpc.irpc_uptime(io);
	if (status.is_ok != true) {
		return "NOT RESPONDING";
	}

	return "RUNNING";
}

/*
  show status of a stream server
*/
function stream_server_status(name)
{
	var irpc = irpc_init();

	if (!service_enabled(name)) {
		return "DISABLED";
	}
	status = irpc.connect(name + "_server");
	if (status.is_ok != true) {
		return "0 connections";
	}

	var io = irpcObj();
	status = irpc.irpc_uptime(io);
	if (status.is_ok != true) {
		return "NOT RESPONDING";
	}

	var n = io.results.length;
	return sprintf("%u connection%s", n, plural(n));
}
