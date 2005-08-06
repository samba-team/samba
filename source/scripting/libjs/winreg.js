/*
	winreg rpc utility functions 
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/	


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
	
	var handle = winreg_open_hive(reg, components[0]);
	if (handle == undefined) {
		return undefined;
	}

	for (i=1;i<components.length;i++) {
		io = irpcObj();
		io.input.handle  = handle;
		io.input.keyname = components[i];
		io.input.unknown = 0;
		io.input.access_mask = reg.SEC_FLAG_MAXIMUM_ALLOWED;
		var status = reg.winreg_OpenKey(io);
		if (!status.is_ok) {
			return undefined;
		}
		if (io.output.result != "WERR_OK") {
			return undefined;
		}

		handle = io.output.handle;
	}
	return handle;
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
	
	handle = winreg_open_path(reg, path);
	if (handle == undefined) {
		return undefined;
	}

	var io = irpcObj();
	var wtime = new Object();
	wtime.low  = 2147483647;
	wtime.high = 2147483647;
	var keyname = new Object();
	keyname.unknown  = 522;
	keyname.key_name = NULL;

	io.input.handle            = handle;
	io.input.key_name_len      = 0;
	io.input.unknown           = 1044;
	io.input.in_name           = keyname;
	io.input.class             = "";
	io.input.last_changed_time = wtime;
	
	var idx = 0;
	for (idx=0;idx >= 0;idx++) {
		io.input.enum_index        = idx;
		var status = reg.winreg_EnumKey(io);
		if (!status.is_ok) return;
		var out = io.output;
		if (out.result != "WERR_OK") {
			return list;
		}

		list[list.length] = out.out_name.name;
		list.length++;
	}

	return list;
}
