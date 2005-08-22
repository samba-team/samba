/*
	server side js functions for encoding/decoding objects into linear strings

	Copyright Andrew Tridgell 2005
	released under the GNU GPL Version 2 or later
*/
/*
	usage:

	  enc = encodeObject(obj);
	  obj = decodeObject(enc);

       The encoded format of the object is a string that is safe to
       use in URLs

       Note that only data elements are encoded, not functions
*/

function __count_members(o) {
	var i, count = 0;
	for (i in o) { 
		count++;  
	}
	if (o.length != undefined) {
		count++;
	}
	return count;
}

function __replace(str, old, rep) {
	var s = string_init();
	var a = s.split(old, str);
	var j = s.join(rep, a);
	return s.join(rep, a);
}

function encodeElement(e, name) {
	var t = typeof(e);
	var r;
	var s = string_init();
	if (t == 'object' && e == null) {
		t = 'null';
	}
	if (t == 'object') {
		r = s.sprintf("%s:%s:%s", name, t, encodeObject(e));
	} else if (t == "string") {
		var enc = s.encodeURIComponent(e);
		var rep = __replace(enc, '%', '#');
		r = s.sprintf("%s:%s:%s:", 
			      name, t, __replace(s.encodeURIComponent(e),'%','#'));
	} else if (t == "boolean" || t == "number") {
		r = s.sprintf("%s:%s:%s:", name, t, "" + e);
	} else if (t == "undefined" || t == "null") {
		r = s.sprintf("%s:%s:", name, t);
	} else if (t == "pointer") {
		r = s.sprintf("%s:string:(POINTER):", name);
	} else {
		println("Unable to linearise type " + t);
		r = "";
	}
	return r;
}

function encodeObject(o) {
	var s = string_init();
	var i, r = s.sprintf("%u:", __count_members(o));
	for (i in o) {
		r = r + encodeElement(o[i], i);
	}
	if (o.length != undefined) {
		r = r + encodeElement(o.length, 'length');
	}
	return r;
}

function decodeObjectArray(a) {
	var s = string_init();
	var o = new Object();
	var i, count = a[a.i]; a.i++;
	for (i=0;i<count;i++) {
		var name  = a[a.i]; a.i++;
		var type  = a[a.i]; a.i++;
		var value;
		if (type == 'object') {
			o[name] = decodeObjectArray(a);
		} else if (type == "string") {
			value = s.decodeURIComponent(__replace(a[a.i],'#','%')); a.i++;
			o[name] = value;
		} else if (type == "boolean") {
			value = a[a.i]; a.i++;
			if (value == 'true') {
				o[name] = true;
			} else {
				o[name] = false;
			}
		} else if (type == "undefined") {
			o[name] = undefined;
		} else if (type == "null") {
			o[name] = null;
		} else if (type == "number") {
			value = a[a.i]; a.i++;
			o[name] = value + 0;
		} else {
			println("Unable to delinearise type " + t);
			assert(t == "supported type");
		}
	}
	return o;
}

function decodeObject(str) {
	var s = string_init();
	var a = s.split(':', str);
	a.i = 0;
	return decodeObjectArray(a);
}
