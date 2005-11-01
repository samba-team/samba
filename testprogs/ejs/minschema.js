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
			 "verbose");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}
verbose = options["verbose"];

if (options.ARGV.length != 2) {
   println("Usage: minschema.js <URL> <classfile>");
   return -1;
}

var url = options.ARGV[0];
var classfile = options.ARGV[1];


var ok = ldb.connect(url);
assert(ok);

objectclasses = new Object();
attributes = new Object();
rootDse = new Object();


/* the attributes we need for objectclasses */
class_attrs = new Array("objectClass", 
			"auxiliaryClass", "systemAuxiliaryClass",
			"possSuperiors", "systemPossSuperiors",
			"lDAPDisplayName", "governsID",
			"rDNAttID", "mustContain", "systemMustContain",
			"mayContain", "systemMayContain",
			"objectClassCategory", "subClassOf", 
			"defaultObjectCategory", "defaultHidingValue", 
			"systemFlags", "systemOnly", "defaultSecurityDescriptor",
			"objectCategory");

attrib_attrs = new Array("objectClass", "lDAPDisplayName", 
			 "isSingleValued", "linkID", "systemFlags", "systemOnly",
			 "schemaIDGUID", "adminDisplayName", "attributeID",
			 "attributeSyntax");

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

/*
  create an objectclass object
*/
function obj_objectClass(name) {
	var o = new Object();
	o.name = name;
	return o;
}

/*
  create an attribute object
*/
function obj_attribute(name) {
	var o = new Object();
	o.name = name;
	return o;
}


/*
  fix a string DN to use ${BASEDN}
*/
function fix_dn(dn) {
	var s = strstr(dn, rootDse.defaultNamingContext);
	if (s == NULL) {
		return dn;
	}
	return substr(dn, 0, strlen(dn) - strlen(s)) + "${BASEDN}";
}

/*
  dump an object as ldif
*/
function write_ldif_one(o, attrs) {
	var i;
	printf("dn: CN=%s,CN=Schema,CN=Configuration,${BASEDN}\n", o.name);
	printf("name: %s\n", o.name);
	for (i=0;i<attrs.length;i++) {
		var a = attrs[i];
		if (o[a] == undefined) {
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
				objectclasses[name] = obj_objectClass(name);
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
				attributes[a] = obj_attribute(a);
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
			attributes[a] = obj_attribute(a);
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
				objectclasses[objectClass] = obj_objectClass(objectClass);
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
	/* not implemented yet */
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
	return obj_objectClass(name);
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
	var i;
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
	       attrib.attributeID, attrib.name, attrib.attributeSyntax);
	if (attrib['isSingleValued'] == "TRUE") {
		printf("SINGLE-VALUE ");
	}
	printf(")\n");
}


/*
  write the aggregate record
*/
function write_aggregate() {
	printf("dn: CN=Aggregate,CN=Schema,CN=Configuration,${BASEDN}\n");
	print("objectClass: top
objectClass: subSchema
cn: Aggregate
distinguishedName: CN=Aggregate,CN=Schema,CN=Configuration,${BASEDN}
instanceType: 4
name: Aggregate
objectCategory: CN=SubSchema,CN=Schema,CN=Configuration,${BASEDN}
");
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
for (i in objectclasses) {
	expand_objectclass(ldb, objectclasses[i]);
}

/*
  find objectclass properties
*/
for (i in objectclasses) {
	find_objectclass_properties(ldb, objectclasses[i]);
}

/*
  trim the 'may' attribute lists to those really needed
*/
for (i in objectclasses) {
	trim_objectclass_attributes(ldb, objectclasses[i]);
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
  dump an ldif form of the attributes and objectclasses
*/
write_ldif(attributes, attrib_attrs);
write_ldif(objectclasses, class_attrs);

write_aggregate();

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
