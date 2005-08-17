/*
	winreg rpc utility functions 
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/	

libinclude("base.js");

/*
  close a handle
*/
function winreg_close(reg, handle)
{
	var io = irpcObj();
	io.input.handle = handle;
	reg.winreg_CloseKey(io);
}


/*
  open a hive
*/
function winreg_open_hive(reg, hive)
{
	var io = irpcObj();
	io.input.system_name = NULL;
	io.input.access_required = reg.SEC_FLAG_MAXIMUM_ALLOWED;
	var status;
	if (hive == "HKLM") {
		status = reg.winreg_OpenHKLM(io);
	} else if (hive == "HKCR") {
		status = reg.winreg_OpenHKCR(io);
	} else if (hive == "HKPD") {
		status = reg.winreg_OpenHKPD(io);
	} else if (hive == "HKU") {
		status = reg.winreg_OpenHKU(io);
	} else {
		println("Unknown hive " + hive);
		return undefined;
	}
	if (!status.is_ok) {
		return undefined;
	}
	return io.output.handle;
}

/*
  open a handle to a path
*/
function winreg_open_path(reg, path)
{
	var s = string_init();
	var i, components = s.split('\\', path);
	var list = new Object();

	list.length = 0;

	/* cope with a leading slash */
	if (components[0] == '') {
		for (i=0;i<(components.length-1);i++) {
			components[i] = components[i+1];
		}
		components.length--;
	}
	
	if (components.length == 0) {
		return undefined;
	}

	var handle = winreg_open_hive(reg, components[0]);
	if (handle == undefined) {
		return undefined;
	}

	if (components.length == 1) {
		return handle;
	}

	var hpath = components[1];

	for (i=2;i<components.length;i++) {
		hpath = hpath + "\\" + components[i];
	}

	io = irpcObj();
	io.input.handle  = handle;
	io.input.keyname = hpath;
	io.input.unknown = 0;
	io.input.access_mask = reg.SEC_FLAG_MAXIMUM_ALLOWED;
	var status = reg.winreg_OpenKey(io);

	winreg_close(reg, handle);

	if (!status.is_ok) {
		return undefined;
	}
	if (io.output.result != "WERR_OK") {
		return undefined;
	}
	
	return io.output.handle;
}

/*
	return a list of keys for a winreg server given a path
	usage:
	   list = winreg_enum_path(reg, path);
*/
function winreg_enum_path(reg, path)
{
	var list = new Object();
	list.length = 0;

	if (path == null || path == "\\" || path == "") {
		return new Array("HKLM", "HKU");
	}
	
	var handle = winreg_open_path(reg, path);
	if (handle == undefined) {
		return undefined;
	}

	var io = irpcObj();
	io.input.handle            = handle;
	io.input.name = new Object();
	io.input.name.length = 0;
	io.input.name.size   = 32;
	io.input.name.name   = NULL;
	io.input.class = new Object();
	io.input.class.length = 0;
	io.input.class.size   = 1024;
	io.input.class.name   = NULL;
	io.input.last_changed_time = 0;

	var idx = 0;
	for (idx=0;idx >= 0;idx++) {
		io.input.enum_index = idx;
		var status = reg.winreg_EnumKey(io);
		if (!status.is_ok) {
			winreg_close(reg, handle);
			return list;
		}
		var out = io.output;
		if (out.result == "WERR_MORE_DATA") {
			io.input.name.size = io.input.name.size * 2;
			idx--;
			if (io.input.name.size > 32000) {
				winreg_close(reg, handle);
				return list;
			}
			continue;
		}
		if (out.result != "WERR_OK") {
			winreg_close(reg, handle);
			return list;
		}
		list[list.length] = out.name.name;
		list.length++;
	}

	winreg_close(reg, handle);
	return list;
}


/*
	return a list of values for a winreg server given a path
	usage:
	   list = winreg_enum_values(reg, path);

	each returned list element is an object containing a name, a
	type and a value
*/
function winreg_enum_values(reg, path)
{
	var list = new Object();
	list.length = 0;

	var handle = winreg_open_path(reg, path);
	if (handle == undefined) {
		return undefined;
	}

	var io = irpcObj();
	io.input.handle      = handle;
	io.input.name        = new Object();
	io.input.name.length = 0;
	io.input.name.size   = 128;
	io.input.name.name   = "";
	io.input.type        = 0;
	io.input.value       = new Array(0);
	io.input.size        = 1024;
	io.input.length      = 0;

	var idx;
	for (idx=0;idx >= 0;idx++) {
		io.input.enum_index = idx;
		var status = reg.winreg_EnumValue(io);
		if (!status.is_ok) {
			winreg_close(reg, handle);
			return list;
		}
		var out = io.output;
		if (out.result == "WERR_MORE_DATA") {
			io.input.size = io.input.size * 2;
			io.input.name.size = io.input.name.size * 2;
			idx--;
			/* limit blobs to 1M */
			if (io.input.size > 1000000) {
				winreg_close(reg, handle);
				return list;
			}
			continue;
		}
		if (out.result != "WERR_OK") {
			winreg_close(reg, handle);
			return list;
		}
		var el   = new Object();
		el.name  = out.name.name;
		el.type  = out.type;
		el.value = out.value;
		el.size  = out.size;
		list[list.length] = el;
		list.length++;
	}

	winreg_close(reg, handle);
	return list;
}
