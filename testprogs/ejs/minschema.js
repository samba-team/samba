#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
  work out the minimal schema for a set of objectclasses 
*/

libinclude("base.js");

var ldb = ldb_init();

var options = GetOptions(ARGV, 
			 "POPT_AUTOHELP",
			 "POPT_COMMON_SAMBA",
			 "POPT_COMMON_CREDENTIALS",
			 "verbose",
			 "classes",
			 "attributes",
			 "subschema",
			 "subschema-auto");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}
verbose = options["verbose"];
dump_all = "yes";
dump_classes = options["classes"];
dump_attributes = options["attributes"];
dump_subschema = options["subschema"];
dump_subschema_auto = options["subschema-auto"];

if (dump_classes != undefined) {
	dump_all = undefined;
}
if (dump_attributes != undefined) {
	dump_all = undefined;
}
if (dump_subschema != undefined) {
	dump_all = undefined;
}
if (dump_subschema_auto != undefined) {
	dump_all = undefined;
	dump_subschema = "yes";
}
if (dump_all != undefined) {
	dump_classes = "yes";
	dump_attributes = "yes";
	dump_subschema = "yes";
	dump_subschema_auto = "yes";
}

if (options.ARGV.length != 2) {
   println("Usage: minschema.js <URL> <classfile>");
   return -1;
}

var url = options.ARGV[0];
var classfile = options.ARGV[1];

/* use command line creds if available */
ldb.credentials = options.get_credentials();

var ok = ldb.connect(url);
assert(ok);

objectclasses = new Object();
attributes = new Object();
rootDse = new Object();

objectclasses_expanded = new Object();

/* the attributes we need for objectclasses */
class_attrs = new Array("objectClass",
			"subClassOf",
			"governsID",
			"possSuperiors",
			"mayContain",
			"mustContain",
			"auxiliaryClass",
			"rDNAttID",
			"showInAdvancedViewOnly",
			"adminDisplayName",
			"adminDescription",
			"objectClassCategory",
			"lDAPDisplayName",
			"schemaIDGUID",
			"systemOnly",
			"systemPossSuperiors",
			"systemMayContain",
			"systemMustContain",
			"systemAuxiliaryClass",
			"defaultSecurityDescriptor",
			"systemFlags",
			"defaultHidingValue",
			"objectCategory",
			"defaultObjectCategory",

			/* this attributes are not used by w2k3 */
			"schemaFlagsEx",
			"msDs-IntId",
			"msDs-Schema-Extensions",
			"classDisplayName",
			"isDefunct");


attrib_attrs = new Array("objectClass",
			 "attributeID",
			 "attributeSyntax",
			 "isSingleValued",
			 "rangeLower",
			 "rangeUpper",
			 "mAPIID",
			 "linkID",
			 "showInAdvancedViewOnly",
			 "adminDisplayName",
			 "oMObjectClass",
			 "adminDescription",
			 "oMSyntax",
			 "searchFlags",
			 "extendedCharsAllowed",
			 "lDAPDisplayName",
			 "schemaIDGUID",
			 "attributeSecurityGUID",
			 "systemOnly",
			 "systemFlags",
			 "isMemberOfPartialAttributeSet",
			 "objectCategory",

			 /* this attributes are not used by w2k3 */
			 "schemaFlagsEx",
			 "msDs-IntId",
			 "msDs-Schema-Extensions",
			 "classDisplayName",
			 "isEphemeral",
			 "isDefunct");

/*
  notes:

  objectClassCategory 
      1: structural
      2: abstract
      3: auxiliary
*/


/*
  print only if verbose is set
*/
function dprintf() {
	if (verbose != undefined) {
		print(vsprintf(arguments));
	}
}

function get_object_cn(ldb, name) {
	var attrs = new Array("cn");

	var res = ldb.search(sprintf("(ldapDisplayName=%s)", name), rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs);
	assert(res != undefined);
	assert(res.length == 1);

        var cn = res[0]["cn"];
	assert(cn != undefined);
	if (typeof(cn) == "string") {
		return cn;
	}
	return cn[0];
}
/*
  create an objectclass object
*/
function obj_objectClass(ldb, name) {
	var o = new Object();
	o.name = name;
	o.cn = get_object_cn(ldb, name);
	return o;
}

/*
  create an attribute object
*/
function obj_attribute(ldb, name) {
	var o = new Object();
	o.name = name;
	o.cn = get_object_cn(ldb, name);
	return o;
}


syntaxmap = new Object();

syntaxmap['2.5.5.1']  = '1.3.6.1.4.1.1466.115.121.1.12';
syntaxmap['2.5.5.2']  = '1.3.6.1.4.1.1466.115.121.1.38';
syntaxmap['2.5.5.3']  = '1.2.840.113556.1.4.1362';
syntaxmap['2.5.5.4']  = '1.2.840.113556.1.4.905';
syntaxmap['2.5.5.5']  = '1.3.6.1.4.1.1466.115.121.1.26';
syntaxmap['2.5.5.6']  = '1.3.6.1.4.1.1466.115.121.1.36';
syntaxmap['2.5.5.7']  = '1.2.840.113556.1.4.903';
syntaxmap['2.5.5.8']  = '1.3.6.1.4.1.1466.115.121.1.7';
syntaxmap['2.5.5.9']  = '1.3.6.1.4.1.1466.115.121.1.27';
syntaxmap['2.5.5.10'] = '1.3.6.1.4.1.1466.115.121.1.40';
syntaxmap['2.5.5.11'] = '1.3.6.1.4.1.1466.115.121.1.24';
syntaxmap['2.5.5.12'] = '1.3.6.1.4.1.1466.115.121.1.15';
syntaxmap['2.5.5.13'] = '1.3.6.1.4.1.1466.115.121.1.43';
syntaxmap['2.5.5.14'] = '1.2.840.113556.1.4.904';
syntaxmap['2.5.5.15'] = '1.2.840.113556.1.4.907';
syntaxmap['2.5.5.16'] = '1.2.840.113556.1.4.906';
syntaxmap['2.5.5.17'] = '1.3.6.1.4.1.1466.115.121.1.40';

/*
  map some attribute syntaxes from some apparently MS specific
  syntaxes to the standard syntaxes
*/
function map_attribute_syntax(s) {
	if (syntaxmap[s] != undefined) {
		return syntaxmap[s];
	}
	return s;
}


/*
  fix a string DN to use ${SCHEMADN}
*/
function fix_dn(dn) {
	var s = strstr(dn, rootDse.schemaNamingContext);
	if (s == NULL) {
		return dn;
	}
	return substr(dn, 0, strlen(dn) - strlen(s)) + "${SCHEMADN}";
}

/*
  dump an object as ldif
*/
function write_ldif_one(o, attrs) {
	var i;
	printf("dn: CN=%s,${SCHEMADN}\n", o.cn);
	for (i=0;i<attrs.length;i++) {
		var a = attrs[i];
		if (o[a] == undefined) {
			continue;
		}
		/* special case for oMObjectClass, which is a binary object */
		if (a == "oMObjectClass") {
			printf("%s:: %s\n", a, o[a]);
			continue;
		}
		var v = o[a];
		if (typeof(v) == "string") {
			v = new Array(v);
		}
		var j;
		for (j=0;j<v.length;j++) {
			printf("%s: %s\n", a, fix_dn(v[j]));
		}
	}
	printf("\n");
}

/*
  dump an array of objects as ldif
*/
function write_ldif(o, attrs) {
	var i;
	for (i in o) {
		write_ldif_one(o[i], attrs);
	}
}


/*
  create a testDN based an an example DN
  the idea is to ensure we obey any structural rules
*/
function create_testdn(exampleDN) {
	var a = split(",", exampleDN);
	a[0] = "CN=TestDN";
	return join(",", a);
}

/*
  find the properties of an objectclass
 */
function find_objectclass_properties(ldb, o) {
	var res = ldb.search(
		sprintf("(ldapDisplayName=%s)", o.name),
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, class_attrs);
	assert(res != undefined);
	assert(res.length == 1);
	var msg = res[0];
	var a;
	for (a in msg) {
		o[a] = msg[a];
	}
}

/*
  find the properties of an attribute
 */
function find_attribute_properties(ldb, o) {
	var res = ldb.search(
		sprintf("(ldapDisplayName=%s)", o.name),
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrib_attrs);
	assert(res != undefined);
	assert(res.length == 1);
	var msg = res[0];
	var a;
	for (a in msg) {
		/* special case for oMObjectClass, which is a binary object */
		if (a == "oMObjectClass") {
			o[a] = ldb.encode(msg[a]);
			continue;
		}
		o[a] = msg[a];
	}
}

/*
  find the auto-created properties of an objectclass. Only works for classes
  that can be created using just a DN and the objectclass
 */
function find_objectclass_auto(ldb, o) {
	if (o["exampleDN"] == undefined) {
		return;
	}
	var testdn = create_testdn(o.exampleDN);
	var ok;

	dprintf("testdn is '%s'\n", testdn);

	var ldif = "dn: " + testdn;
	ldif = ldif + "\nobjectClass: " + o.name;
	ok = ldb.add(ldif);
	if (!ok) {
		dprintf("error adding %s: %s\n", o.name, ldb.errstring());
		dprintf("%s\n", ldif);
		return;
	}

	var res = ldb.search("", testdn, ldb.SCOPE_BASE);
	ok = ldb.del(testdn);
	assert(ok);

	var a;
	for (a in res[0]) {
		attributes[a].autocreate = true;
	}
}


/*
  look at auxiliary information from a class to intuit the existance of more
  classes needed for a minimal schema
*/
function expand_objectclass(ldb, o) {
	var attrs = new Array("auxiliaryClass", "systemAuxiliaryClass",
			      "possSuperiors", "systemPossSuperiors",
			      "subClassOf");
	var res = ldb.search(
		sprintf("(&(objectClass=classSchema)(ldapDisplayName=%s))", o.name),
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs);
	var a;
	dprintf("Expanding class %s\n", o.name);
	assert(res != undefined);
	assert(res.length == 1);
	var msg = res[0];
	for (a=0;a<attrs.length;a++) {
		var aname = attrs[a];
		if (msg[aname] == undefined) {
			continue;
		}
		var list = msg[aname];
		if (typeof(list) == "string") {
			list = new Array(msg[aname]);
		}
		var i;
		for (i=0;i<list.length;i++) {
			var name = list[i];
			if (objectclasses[name] == undefined) {
				dprintf("Found new objectclass '%s'\n", name);
				objectclasses[name] = obj_objectClass(ldb, name);
			}
		}
	}
}


/*
  add the must and may attributes from an objectclass to the full list
  of attributes
*/
function add_objectclass_attributes(ldb, class) {
	var attrs = new Array("mustContain", "systemMustContain", 
			      "mayContain", "systemMayContain");
	var i;
	for (i=0;i<attrs.length;i++) {
		var aname = attrs[i];
		if (class[aname] == undefined) {
			continue;
		}
		var alist = class[aname];
		if (typeof(alist) == "string") {
			alist = new Array(alist);
		}
		var j;
		var len = alist.length;
		for (j=0;j<len;j++) {
			var a = alist[j];
			if (attributes[a] == undefined) {
				attributes[a] = obj_attribute(ldb, a);
			}
		}
	}
}


/*
  process an individual record, working out what attributes it has
*/
function walk_dn(ldb, dn) {
	/* get a list of all possible attributes for this object */
	var attrs = new Array("allowedAttributes");
	var res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, attrs);
	if (res == undefined) {
		dprintf("Unable to fetch allowedAttributes for '%s' - %s\n", 
		       dn, ldb.errstring());
		return;
	}
	var allattrs = res[0].allowedAttributes;
	res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, allattrs);
	if (res == undefined) {
		dprintf("Unable to fetch all attributes for '%s' - %s\n", 
		       dn, ldb.errstring());
		return;
	}
	var a;
	var msg = res[0];
	for (a in msg) {
		if (attributes[a] == undefined) {
			attributes[a] = obj_attribute(ldb, a);
		}
	}
}

/*
  walk a naming context, looking for all records
*/
function walk_naming_context(ldb, namingContext) {
	var attrs = new Array("objectClass");
	var res = ldb.search("objectClass=*", namingContext, ldb.SCOPE_DEFAULT, attrs);
	if (res == undefined) {
		dprintf("Unable to fetch objectClasses for '%s' - %s\n", 
		       namingContext, ldb.errstring());
		return;
	}
	var r;
	for (r=0;r<res.length;r++) {
		var msg = res[r].objectClass;
		var c;
		for (c=0;c<msg.length;c++) {
			var objectClass = msg[c];
			if (objectclasses[objectClass] == undefined) {
				objectclasses[objectClass] = obj_objectClass(ldb, objectClass);
				objectclasses[objectClass].exampleDN = res[r].dn;
			}
		}
		walk_dn(ldb, res[r].dn);
	}
}

/*
  trim the may attributes for an objectClass
*/
function trim_objectclass_attributes(ldb, class) {
	var i,j,n;

	/* trim possibleInferiors,
	 * include only the classes we extracted */
	var possinf = class["possibleInferiors"];
	if (possinf != undefined) {
		var newpossinf = new Array();
		if (typeof(possinf) == "string") {
			possinf = new Array(possinf);
		}
		n = 0;
		for (j = 0;j < possinf.length; j++) {
			var x = possinf[j];
			if (objectclasses[x] != undefined) {
				newpossinf[n] = x;
				n++;
			}
		}
		class["possibleInferiors"] = newpossinf;
	}

	/* trim systemMayContain,
	 * remove duplicates */
	var sysmay = class["systemMayContain"];
	if (sysmay != undefined) {
		var newsysmay = new Array();
		if (typeof(sysmay) == "string") {
			sysmay = new Array(sysmay);
		}
		for (j = 0;j < sysmay.length; j++) {
			var x = sysmay[j];
			var dup = false;
			if (newsysmay[0] == undefined) {
				newsysmay[0] = x;
			} else {
				for (n = 0; n < newsysmay.length; n++) {
					if (newsysmay[n] == x) {
						dup = true;
					}
				}
				if (dup == false) {
					newsysmay[n] = x;
				}
			}
		}
		class["systemMayContain"] = newsysmay;
	}

	/* trim mayContain,
	 * remove duplicates */
	var may = class["mayContain"];
	if (may != undefined) {
		var newmay = new Array();
		if (typeof(may) == "string") {
			may = new Array(may);
		}
		for (j = 0;j < may.length; j++) {
			var x = may[j];
			var dup = false;
			if (newmay[0] == undefined) {
				newmay[0] = x;
			} else {
				for (n = 0; n < newmay.length; n++) {
					if (newmay[n] == x) {
						dup = true;
					}
				}
				if (dup == false) {
					newmay[n] = x;
				}
			}
		}
		class["mayContain"] = newmay;
	}
}

/*
  load the basic attributes of an objectClass
*/
function build_objectclass(ldb, name) {
	var attrs = new Array("name");
	var res = ldb.search(
		sprintf("(&(objectClass=classSchema)(ldapDisplayName=%s))", name),
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs);
	if (res == undefined) {
		dprintf("unknown class '%s'\n", name);
		return undefined;
	}
	if (res.length == 0) {
		dprintf("unknown class '%s'\n", name);
		return undefined;
	}
	return obj_objectClass(ldb, name);
}

/*
  append 2 lists
*/
function list_append(a1, a2) {
	var i;
	if (a1 == undefined) {
		return a2;
	}
	if (a2 == undefined) {
		return a1;
	}
	for (i=0;i<a2.length;i++) {
		a1[a1.length] = a2[i];
	}
	return a1;
}

/*
  form a coalesced attribute list
*/
function attribute_list(class, attr1, attr2) {
	var a1 = class[attr1];
	var a2 = class[attr2];
	if (typeof(a1) == "string") {
		a1 = new Array(a1);
	}
	if (typeof(a2) == "string") {
		a2 = new Array(a2);
	}
	return list_append(a1, a2);
}

/*
  write out a list in aggregate form
*/
function aggregate_list(name, list) {
	if (list == undefined) {
		return;
	}
	var i;
	printf("%s ( ", name);
	for (i=0;i<list.length;i++) {
		printf("%s ", list[i]);
		if (i < (list.length - 1)) {
			printf("$ ");
		}
	}
	printf(") ");
}

/*
  write the aggregate record for an objectclass
*/
function write_aggregate_objectclass(class) {
	printf("objectClasses: ( %s NAME '%s' ", class.governsID, class.name);
	if (class['subClassOf'] != undefined) {
		printf("SUP %s ", class['subClassOf']);
	}
	if (class.objectClassCategory == 1) {
		printf("STRUCTURAL ");
	} else if (class.objectClassCategory == 2) {
		printf("ABSTRACT ");
	} else if (class.objectClassCategory == 3) {
		printf("AUXILIARY ");
	}

	var list;

	list = attribute_list(class, "systemMustContain", "mustContain");
	aggregate_list("MUST", list);

	list = attribute_list(class, "systemMayContain", "mayContain");
	aggregate_list("MAY", list);

	printf(")\n");
}


/*
  write the aggregate record for an ditcontentrule
*/
function write_aggregate_ditcontentrule(class) {
	var list = attribute_list(class, "auxiliaryClass", "systemAuxiliaryClass");
	var i;
	if (list == undefined) {
		return;
	}

	printf("dITContentRules: ( %s NAME '%s' ", class.governsID, class.name);

	aggregate_list("AUX", list);

	var may_list = undefined;
	var must_list = undefined;

	for (i=0;i<list.length;i++) {
		var c = list[i];
		var list2;
		list2 = attribute_list(objectclasses[c], 
				       "mayContain", "systemMayContain");
		may_list = list_append(may_list, list2);
		list2 = attribute_list(objectclasses[c], 
				       "mustContain", "systemMustContain");
		must_list = list_append(must_list, list2);
	}

	aggregate_list("MUST", must_list);
	aggregate_list("MAY", may_list);

	printf(")\n");
}

/*
  write the aggregate record for an attribute
*/
function write_aggregate_attribute(attrib) {
	printf("attributeTypes: ( %s NAME '%s' SYNTAX '%s' ", 
	       attrib.attributeID, attrib.name, 
	       map_attribute_syntax(attrib.attributeSyntax));
	if (attrib['isSingleValued'] == "TRUE") {
		printf("SINGLE-VALUE ");
	}
	if (attrib['systemOnly'] == "TRUE") {
		printf("NO-USER-MODIFICATION ");
	}

	printf(")\n");
}


/*
  write the aggregate record
*/
function write_aggregate() {
	printf("dn: CN=Aggregate,${SCHEMADN}\n");
	print("objectClass: top
objectClass: subSchema
objectCategory: CN=SubSchema,${SCHEMADN}
");
	if (dump_subschema_auto == undefined) {
		return;	
	}

	for (i in objectclasses) {
		write_aggregate_objectclass(objectclasses[i]);
	}
	for (i in attributes) {
		write_aggregate_attribute(attributes[i]);
	}
	for (i in objectclasses) {
		write_aggregate_ditcontentrule(objectclasses[i]);
	}
}

/*
  load a list from a file
*/
function load_list(file) {
	var sys = sys_init();
	var s = sys.file_load(file);
	var a = split("\n", s);
	return a;
}

/* get the rootDSE */
var res = ldb.search("", "", ldb.SCOPE_BASE);
rootDse = res[0];

/* load the list of classes we are interested in */
var classes = load_list(classfile);
var i;
for (i=0;i<classes.length;i++) {
	var classname = classes[i];
	var class = build_objectclass(ldb, classname);
	if (class != undefined) {
		objectclasses[classname] = class;
	}
}


/*
  expand the objectclass list as needed
*/
var num_classes = 0;
var expanded = 0;
/* calculate the actual number of classes */
for (i in objectclasses) {
	num_classes++;
}
/* so EJS do not have while nor the break statement
   cannot find any other way than doing more loops
   than necessary to recursively expand all classes
 */
var inf;
for (inf = 0;inf < 500; inf++) {
	if (expanded < num_classes) {
		for (i in objectclasses) {
			var n = objectclasses[i];
			if (objectclasses_expanded[i] != "DONE") {
				expand_objectclass(ldb, objectclasses[i]);
				objectclasses_expanded[i] = "DONE";
				expanded++;
			}
		}
		/* recalculate the actual number of classes */
		num_classes = 0;
		for (i in objectclasses) {
			num_classes++;
		}
	}
}

/*
  find objectclass properties
*/
for (i in objectclasses) {
	find_objectclass_properties(ldb, objectclasses[i]);
}

/*
  form the full list of attributes
*/
for (i in objectclasses) {
	add_objectclass_attributes(ldb, objectclasses[i]);
}

/* and attribute properties */
for (i in attributes) {
	find_attribute_properties(ldb, attributes[i]);
}

/*
  trim the 'may' attribute lists to those really needed
*/
for (i in objectclasses) {
	trim_objectclass_attributes(ldb, objectclasses[i]);
}

/*
  dump an ldif form of the attributes and objectclasses
*/
if (dump_attributes != undefined) {
	write_ldif(attributes, attrib_attrs);
}
if (dump_classes != undefined) {
	write_ldif(objectclasses, class_attrs);
}
if (dump_subschema != undefined) {
	write_aggregate();
}

if (verbose == undefined) {
	exit(0);
}

/*
  dump list of objectclasses
*/
printf("objectClasses:\n")
for (i in objectclasses) {
	printf("\t%s\n", i);
}
printf("attributes:\n")
for (i in attributes) {
	printf("\t%s\n", i);
}

printf("autocreated attributes:\n");
for (i in attributes) {
	if (attributes[i].autocreate == true) {
		printf("\t%s\n", i);
	}
}

return 0;
