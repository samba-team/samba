/*
	samr rpc utility functions 
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/	

if (global["HAVE_SAMR_JS"] != undefined) {
   return;
}
HAVE_SAMR_JS=1

/*
  return a list of names and indexes from a samArray
*/
function samArray(output)
{
	var list = new Array(output.num_entries);
	if (output.sam == NULL) {
		return list;
	}
	var i, entries = output.sam.entries;
	for (i=0;i<output.num_entries;i++) {
		list[i] = new Object();
                list[i].name = entries[i].name;
                list[i].idx  = entries[i].idx;
	}
	return list;
}

/*
	connect to the sam database
*/
function samrConnect(conn)
{
	security_init(conn);
	var io = irpcObj();
	io.input.system_name = NULL;
	io.input.access_mask = conn.SEC_FLAG_MAXIMUM_ALLOWED;
	var status = conn.samr_Connect2(io);
	check_status_ok(status);
	return io.output.connect_handle;
}

/*
	close a handle
*/
function samrClose(conn, handle)
{
	var io = irpcObj();
	io.input.handle = handle;
	var status = conn.samr_Close(io);
	check_status_ok(status);
}

/*
   get the sid for a domain
*/
function samrLookupDomain(conn, handle, domain)
{
	var io = irpcObj();
	io.input.connect_handle = handle;
	io.input.domain_name = domain;
	var status = conn.samr_LookupDomain(io);
	check_status_ok(status);
	return io.output.sid;
}

/*
  open a domain by sid
*/
function samrOpenDomain(conn, handle, sid)
{
	var io = irpcObj();
	io.input.connect_handle = handle;
	io.input.access_mask = conn.SEC_FLAG_MAXIMUM_ALLOWED;
	io.input.sid = sid;
	var status = conn.samr_OpenDomain(io);
	check_status_ok(status);
	return io.output.domain_handle;
}

/*
  open a user by rid
*/
function samrOpenUser(conn, handle, rid)
{
	var io = irpcObj();
	io.input.domain_handle = handle;
	io.input.access_mask = conn.SEC_FLAG_MAXIMUM_ALLOWED;
	io.input.rid = rid;
	var status = conn.samr_OpenUser(io);
	check_status_ok(status);
	return io.output.user_handle;
}

/*
  return a list of all users
*/
function samrEnumDomainUsers(conn, dom_handle)
{
	var io = irpcObj();
	io.input.domain_handle = dom_handle;
	io.input.resume_handle = 0;
	io.input.acct_flags = 0;
	io.input.max_size = -1;
	var status = conn.samr_EnumDomainUsers(io);
	check_status_ok(status);
	return samArray(io.output);
}

/*
  return a list of all groups
*/
function samrEnumDomainGroups(conn, dom_handle)
{
	var io = irpcObj();
	io.input.domain_handle = dom_handle;
	io.input.resume_handle = 0;
	io.input.acct_flags = 0;
	io.input.max_size = -1;
	var status = conn.samr_EnumDomainGroups(io);
	check_status_ok(status);
	return samArray(io.output);
}

/*
  return a list of domains
*/
function samrEnumDomains(conn, handle)
{
	var io = irpcObj();
	io.input.connect_handle = handle;
	io.input.resume_handle = 0;
	io.input.buf_size = -1;
	var status = conn.samr_EnumDomains(io);
	check_status_ok(status);
	return samArray(io.output);
}

/*
  return information about a user
*/
function samrQueryUserInfo(conn, user_handle, level)
{
	var r, io = irpcObj();
	io.input.user_handle = user_handle;
	io.input.level = level;
	var status = conn.samr_QueryUserInfo(io);
	check_status_ok(status);
	return io.output.info.info3;
}


/*
  fill a user array with user information from samrQueryUserInfo
*/
function samrFillUserInfo(conn, dom_handle, users, level)
{
	var i;
	for (i=0;i<users.length;i++) {
		var r, user_handle, info;
		user_handle = samrOpenUser(conn, dom_handle, users[i].idx);
		info = samrQueryUserInfo(conn, user_handle, level);
		info.name = users[i].name;
		info.idx  = users[i].idx;
		users[i] = info;
		samrClose(conn, user_handle);
	}
}

