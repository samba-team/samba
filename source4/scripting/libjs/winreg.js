/*
	winreg rpc utility functions 
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/	

libinclude("base.js");

/*
  close a handle
*/
function __winreg_close(handle)
{
	var io = irpcObj();
	io.input.handle = handle;
	this.winreg_CloseKey(io);
}


/*
  open a hive
*/
function __winreg_open_hive(hive)
{
	var io = irpcObj();
	io.input.system_name = NULL;
	io.input.access_mask = this.SEC_FLAG_MAXIMUM_ALLOWED;
	var status;
	if (hive == "HKLM") {
		status = this.winreg_OpenHKLM(io);
	} else if (hive == "HKCR") {
		status = this.winreg_OpenHKCR(io);
	} else if (hive == "HKPD") {
		status = this.winreg_OpenHKPD(io);
	} else if (hive == "HKU") {
		status = this.winreg_OpenHKU(io);
	} else {
		this._last_error = "Unknown hive " + hive;
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
function __winreg_open_path(path)
{
	var s = string_init();
	var i, components = s.split('\\', path);

	/* cope with a leading slash */
	if (components[0] == '') {
		for (i=0;i<(components.length-1);i++) {
			components[i] = components[i+1];
		}
		delete(components[i]);
	}
	
	if (components.length == 0) {
		return undefined;
	}

	var handle = this.open_hive(components[0]);
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
	io.input.parent_handle  = handle;
	io.input.keyname = hpath;
	io.input.unknown = 0;
	io.input.access_mask = this.SEC_FLAG_MAXIMUM_ALLOWED;
	var status = this.winreg_OpenKey(io);

	this.close(handle);

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
	   list = reg.enum_path(path);
*/
function __winreg_enum_path(path)
{
	var list = new Array(0);

	if (path == null || path == "\\" || path == "") {
		return new Array("HKLM", "HKU");
	}
	
	var handle = this.open_path(path);
	if (handle == undefined) {
		return undefined;
	}

	var io = irpcObj();
	io.input.handle            = handle;
	io.input.name = new Object();
	io.input.name.length = 0;
	io.input.name.size   = 32;
	io.input.name.name   = NULL;
	io.input.keyclass = new Object();
	io.input.keyclass.length = 0;
	io.input.keyclass.size   = 1024;
	io.input.keyclass.name   = NULL;
	io.input.last_changed_time = 0;

	var idx = 0;
	for (idx=0;idx >= 0;idx++) {
		io.input.enum_index = idx;
		var status = this.winreg_EnumKey(io);
		if (!status.is_ok) {
			this.close(handle);
			return list;
		}
		var out = io.output;
		if (out.result == "WERR_MORE_DATA") {
			io.input.name.size = io.input.name.size * 2;
			idx--;
			if (io.input.name.size > 32000) {
				this.close(handle);
				return list;
			}
			continue;
		}
		if (out.result != "WERR_OK") {
			this.close(handle);
			return list;
		}
		list[list.length] = out.name.name;
	}

	this.close(handle);
	return list;
}


/*
	return a list of values for a winreg server given a path
	usage:
	   list = reg.enum_values(path);

	each returned list element is an object containing a name, a
	type and a value
*/
function __winreg_enum_values(path)
{
	var data = datablob_init();
	var list = new Array(0);

	var handle = this.open_path(path);
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
		var status = this.winreg_EnumValue(io);
		if (!status.is_ok) {
			this.close(handle);
			return list;
		}
		var out = io.output;
		if (out.result == "WERR_MORE_DATA") {
			io.input.size = io.input.size * 2;
			io.input.name.size = io.input.name.size * 2;
			idx--;
			/* limit blobs to 1M */
			if (io.input.size > 1000000) {
				this.close(handle);
				return list;
			}
			continue;
		}
		if (out.result != "WERR_OK") {
			this.close(handle);
			return list;
		}
		var el   = new Object();
		el.name  = out.name.name;
		el.type  = out.type;
		el.rawvalue = out.value;
		el.value = data.regToVar(el.rawvalue, el.type);
		el.size  = out.size;
		list[list.length] = el;
	}

	this.close(handle);
	return list;
}


/*
  create a new key
    ok = reg.create_key(path, key);
*/
function __winreg_create_key(path, key)
{
	var handle = this.open_path(path);
	if (handle == undefined) {
		return undefined;
	}

	var io = irpcObj();
	io.input.handle = handle;
	io.input.name = key;
	io.input.keyclass = NULL;
	io.input.options = 0;
	io.input.access_mask = this.SEC_FLAG_MAXIMUM_ALLOWED;
	io.input.secdesc = NULL;
	io.input.action_taken = 0;	

	var status = this.winreg_CreateKey(io);
	this.close(handle);
	if (!status.is_ok) {
		return false;
	}
	if (io.output.result != "WERR_OK") {
		return false;
	}
	this.close(io.output.new_handle);
	return true;
}


/*
  return a string for a winreg type
*/
function __winreg_typestring(type)
{
	return this.typenames[type];
}

/*
  initialise the winreg lib, returning an object
*/
function winregObj()
{
	var reg = winreg_init();
	security_init(reg);

	reg.typenames = new Array("REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", 
				  "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ",
				  "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", 
				  "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD");

	reg.close       = __winreg_close;
	reg.open_hive   = __winreg_open_hive;
	reg.open_path   = __winreg_open_path;
	reg.enum_path   = __winreg_enum_path;
	reg.enum_values = __winreg_enum_values;
	reg.create_key  = __winreg_create_key;
	reg.typestring  = __winreg_typestring;

	return reg;
}
