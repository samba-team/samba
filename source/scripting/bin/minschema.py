#!/usr/bin/python
# 
#  work out the minimal schema for a set of objectclasses 
#

import getopt
import optparse
import samba

parser = optparse.OptionParser("minschema <URL> <classfile>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option_group(options.VersionOptions(parser))
parser.add_option("--verbose", help="Be verbose", action="store_true")
parser.add_option("--dump-classes", action="store_true")
parser.add_option("--dump-attributes", action="store_true")
parser.add_option("--dump-subschema", action="store_true")
parser.add_option("--dump-subschema-auto", action="store_true")

opts, args = parser.parse_args()
opts.dump_all = True

if opts.dump_classes:
    opts.dump_all = False
if opts.dump_attributes:
    opts.dump_all = False
if opts.dump_subschema:
    opts.dump_all = False
if dump_subschema_auto:
	opts.dump_all = False
	opts.dump_subschema = True
if opts.dump_all:
	opts.dump_classes = True
	opts.dump_attributes = True
	opts.dump_subschema = True
	opts.dump_subschema_auto = True

if len(args) != 2:
    parser.print_usage()
    sys.exit(1)

(url, classfile) = args

creds = credopts.get_credentials()
ldb = Ldb(url, credentials=creds)

objectclasses = []
attributes = []
rootDse = {}

objectclasses_expanded = []

# the attributes we need for objectclasses
class_attrs = ["objectClass", 
               "subClassOf", 
               "governsID", 
               "possSuperiors", 
               "possibleInferiors",
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
               
               # this attributes are not used by w2k3
               "schemaFlagsEx",
               "msDs-IntId",
               "msDs-Schema-Extensions",
               "classDisplayName",
               "isDefunct"]

attrib_attrs = ["objectClass",
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
                
                # this attributes are not used by w2k3
                "schemaFlagsEx",
                "msDs-IntId",
                "msDs-Schema-Extensions",
                "classDisplayName",
                "isEphemeral",
                "isDefunct"]

#
#  notes:
#
#  objectClassCategory 
#      1: structural
#      2: abstract
#      3: auxiliary

#
#  print only if verbose is set
#
def dprintf(text):
    if verbose is not None:
		print text

def get_object_cn(ldb, name):
	attrs = ["cn"]

	res = ldb.search("(ldapDisplayName=%s)" % name, rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs)
	assert len(res) == 1

    cn = res[0]["cn"]

#
#  create an objectclass object
#
def obj_objectClass(ldb, name):
	var o = new Object()
	o.name = name
	o.cn = get_object_cn(ldb, name)
	return o

#
#  create an attribute object
#
def obj_attribute(ldb, name):
	var o = new Object()
	o.name = name
	o.cn = get_object_cn(ldb, name)
	return o


syntaxmap = dict()

syntaxmap['2.5.5.1']  = '1.3.6.1.4.1.1466.115.121.1.12'
syntaxmap['2.5.5.2']  = '1.3.6.1.4.1.1466.115.121.1.38'
syntaxmap['2.5.5.3']  = '1.2.840.113556.1.4.1362'
syntaxmap['2.5.5.4']  = '1.2.840.113556.1.4.905'
syntaxmap['2.5.5.5']  = '1.3.6.1.4.1.1466.115.121.1.26'
syntaxmap['2.5.5.6']  = '1.3.6.1.4.1.1466.115.121.1.36'
syntaxmap['2.5.5.7']  = '1.2.840.113556.1.4.903'
syntaxmap['2.5.5.8']  = '1.3.6.1.4.1.1466.115.121.1.7'
syntaxmap['2.5.5.9']  = '1.3.6.1.4.1.1466.115.121.1.27'
syntaxmap['2.5.5.10'] = '1.3.6.1.4.1.1466.115.121.1.40'
syntaxmap['2.5.5.11'] = '1.3.6.1.4.1.1466.115.121.1.24'
syntaxmap['2.5.5.12'] = '1.3.6.1.4.1.1466.115.121.1.15'
syntaxmap['2.5.5.13'] = '1.3.6.1.4.1.1466.115.121.1.43'
syntaxmap['2.5.5.14'] = '1.2.840.113556.1.4.904'
syntaxmap['2.5.5.15'] = '1.2.840.113556.1.4.907'
syntaxmap['2.5.5.16'] = '1.2.840.113556.1.4.906'
syntaxmap['2.5.5.17'] = '1.3.6.1.4.1.1466.115.121.1.40'

#
#  map some attribute syntaxes from some apparently MS specific
#  syntaxes to the standard syntaxes
#
def map_attribute_syntax(s):
    if syntaxmap.has_key(s):
		return syntaxmap[s]
	return s

#
#  fix a string DN to use ${SCHEMADN}
#
def fix_dn(dn):
	s = strstr(dn, rootDse.schemaNamingContext)
	if (s == NULL) {
		return dn
	}
	return substr(dn, 0, strlen(dn) - strlen(s)) + "${SCHEMADN}"

#
#  dump an object as ldif
#
def write_ldif_one(o, attrs):
	print "dn: CN=%s,${SCHEMADN}\n" % o["cn"]
    for a in attrs:
        if not o.has_key(a):
			continue
		# special case for oMObjectClass, which is a binary object
        if a == "oMObjectClass":
			print "%s:: %s\n" % (a, o[a])
			continue
		v = o[a]
        if isinstance(v, str):
			v = [v]
        for j in v:
			print "%s: %s\n" % (a, fix_dn(j))
	print "\n"

#
# dump an array of objects as ldif
#
def write_ldif(o, attrs):
    for i in o:
		write_ldif_one(i, attrs)


#
#  create a testDN based an an example DN
#  the idea is to ensure we obey any structural rules
#
def create_testdn(exampleDN):
	a = split(",", exampleDN)
	a[0] = "CN=TestDN"
	return ",".join(a)

#
#  find the properties of an objectclass
#
def find_objectclass_properties(ldb, o):
	res = ldb.search(
		expression="(ldapDisplayName=%s)" % o.name,
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, class_attrs)
	assert(len(res) == 1)
    msg = res[0]
    for a in msg:
		o[a] = msg[a]

#
#  find the properties of an attribute
#
def find_attribute_properties(ldb, o):
	res = ldb.search(
		expression="(ldapDisplayName=%s)" % o.name,
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrib_attrs)
	assert(len(res) == 1)
    msg = res[0]
    for a in msg:
		# special case for oMObjectClass, which is a binary object
        if a == "oMObjectClass":
			o[a] = ldb.encode(msg[a])
			continue
		o[a] = msg[a]

#
#  find the auto-created properties of an objectclass. Only works for classes
#  that can be created using just a DN and the objectclass
#
def find_objectclass_auto(ldb, o):
    if not o.has_key("exampleDN"):
		return
	testdn = create_testdn(o.exampleDN)

	print "testdn is '%s'\n" % testdn

	ldif = "dn: " + testdn
	ldif += "\nobjectClass: " + o.name
    try:
        ldb.add(ldif)
    except LdbError, e:
        print "error adding %s: %s\n" % (o.name, e)
		print "%s\n" % ldif
        return

	res = ldb.search("", testdn, ldb.SCOPE_BASE)
	ldb.delete(testdn)

    for a in res.msgs[0]:
		attributes[a].autocreate = True


#
#  look at auxiliary information from a class to intuit the existance of more
#  classes needed for a minimal schema
#
def expand_objectclass(ldb, o):
	attrs = ["auxiliaryClass", "systemAuxiliaryClass",
			      "possSuperiors", "systemPossSuperiors",
			      "subClassOf"]
	res = ldb.search(
		"(&(objectClass=classSchema)(ldapDisplayName=%s))" % o.name,
		rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs)
	print "Expanding class %s\n" % o.name
	assert(len(res) == 1)
	msg = res[0]
    for a in attrs:
        if not msg.has_key(aname):
			continue
		list = msg[aname]
        if isinstance(list, str):
			list = [msg[aname]]
        for name in list:
            if not objectclasses.has_key(name):
				print "Found new objectclass '%s'\n" % name
				objectclasses[name] = obj_objectClass(ldb, name)


#
#  add the must and may attributes from an objectclass to the full list
#  of attributes
#
def add_objectclass_attributes(ldb, class):
	attrs = ["mustContain", "systemMustContain", 
			      "mayContain", "systemMayContain"]
    for aname in attrs:
        if not class.has_key(aname):
			continue
		alist = class[aname]
        if isinstance(alist, str):
			alist = [alist]
        for a in alist:
            if not attributes.has_key(a):
				attributes[a] = obj_attribute(ldb, a)


#
#  process an individual record, working out what attributes it has
#
def walk_dn(ldb, dn):
	# get a list of all possible attributes for this object 
	attrs = ["allowedAttributes"]
    try:
        res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, attrs)
    except LdbError, e:
		print "Unable to fetch allowedAttributes for '%s' - %r\n" % (dn, e)
		return
	allattrs = res[0]["allowedAttributes"]
    try:
        res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, allattrs)
    except LdbError, e:
        print "Unable to fetch all attributes for '%s' - %s\n" % (dn, e)
		return
	msg = res[0]
    for a in msg:
        if not attributes.has_key(a):
			attributes[a] = obj_attribute(ldb, a)

#
#  walk a naming context, looking for all records
#
def walk_naming_context(ldb, namingContext):
    try:
        res = ldb.search("objectClass=*", namingContext, ldb.SCOPE_DEFAULT, 
                         ["objectClass"])
    except LdbError, e:
		print "Unable to fetch objectClasses for '%s' - %s\n" % (namingContext, e)
		return
    for msg in res:
		msg = res.msgs[r]["objectClass"]
        for objectClass in msg:
            if not objectclasses.has_key(objectClass):
				objectclasses[objectClass] = obj_objectClass(ldb, objectClass)
				objectclasses[objectClass].exampleDN = res.msgs[r]["dn"]
		walk_dn(ldb, res.msgs[r].dn)

#
#  trim the may attributes for an objectClass
#
def trim_objectclass_attributes(ldb, class):
	# trim possibleInferiors,
	# include only the classes we extracted
    if class.has_key("possibleInferiors"):
        possinf = class["possibleInferiors"]
		newpossinf = []
        if isinstance(possinf, str):
			possinf = [possinf]
        for x in possinf:
            if objectclasses.has_key(x):
				newpossinf[n] = x
				n++
		class["possibleInferiors"] = newpossinf

	# trim systemMayContain,
	# remove duplicates
    if class.has_key("systemMayContain"):
        sysmay = class["systemMayContain"]
		newsysmay = []
        if isinstance(sysmay, str):
			sysmay = [sysmay]
        for x in sysmay:
			dup = False
			if newsysmay[0] == undefined) {
				newsysmay[0] = x
            else:
				for (n = 0; n < newsysmay.length; n++) {
					if (newsysmay[n] == x) {
						dup = True
                if not dup:
					newsysmay[n] = x
		class["systemMayContain"] = newsysmay

	# trim mayContain,
	# remove duplicates
    if not class.has_key("mayContain"):
        may = class["mayContain"]
		newmay = []
        if isinstance(may, str):
			may = [may]
        for x in may:
			dup = False
			if (newmay[0] == undefined) {
				newmay[0] = x
			} else {
				for (n = 0; n < newmay.length; n++) {
					if (newmay[n] == x) {
						dup = True
                if not dup:
					newmay[n] = x
		class["mayContain"] = newmay

#
#  load the basic attributes of an objectClass
#
def build_objectclass(ldb, name):
	attrs = ["name"]
    try:
        res = ldb.search(
            expression="(&(objectClass=classSchema)(ldapDisplayName=%s))" % name,
            rootDse.schemaNamingContext, ldb.SCOPE_SUBTREE, attrs)
    except LdbError, e:
		print "unknown class '%s'\n" % name
		return None
    if len(res) == 0:
		print "unknown class '%s'\n" % name
		return None
	return obj_objectClass(ldb, name)

#
#  append 2 lists
#
def list_append(a1, a2):
	if (a1 == undefined) {
		return a2
	if (a2 == undefined)
		return a1
    for (i=0;i<a2.length;i++):
		a1[a1.length] = a2[i]
	return a1

#
#  form a coalesced attribute list
#
def attribute_list(class, attr1, attr2):
	a1 = class[attr1]
	a2 = class[attr2]
    if isinstance(a1, str):
		a1 = [a1]
    if isinstance(a2, str):
		a2 = [a2]
	return list_append(a1, a2)

#
#  write out a list in aggregate form
#
def aggregate_list(name, list):
    if list is None:
		return
	print "%s ( %s )" % (name, "$ ".join(list))

#
#  write the aggregate record for an objectclass
#
def write_aggregate_objectclass(class):
	print "objectClasses: ( %s NAME '%s' " % (class.governsID, class.name)
    if not class.has_key('subClassOf'):
		print "SUP %s " % class['subClassOf']
    if class.objectClassCategory == 1:
		print "STRUCTURAL "
    elif class.objectClassCategory == 2:
		print "ABSTRACT "
    elif class.objectClassCategory == 3:
		print "AUXILIARY "

	list = attribute_list(class, "systemMustContain", "mustContain")
	aggregate_list("MUST", list)

	list = attribute_list(class, "systemMayContain", "mayContain")
	aggregate_list("MAY", list)

	print ")\n"


#
#  write the aggregate record for an ditcontentrule
#
def write_aggregate_ditcontentrule(class):
	list = attribute_list(class, "auxiliaryClass", "systemAuxiliaryClass")
    if list is None:
		return

	print "dITContentRules: ( %s NAME '%s' " % (class.governsID, class.name)

	aggregate_list("AUX", list)

	may_list = None
	must_list = None

    for c in list:
		list2 = attribute_list(objectclasses[c], 
				       "mayContain", "systemMayContain")
		may_list = list_append(may_list, list2)
		list2 = attribute_list(objectclasses[c], 
				       "mustContain", "systemMustContain")
		must_list = list_append(must_list, list2)

	aggregate_list("MUST", must_list)
	aggregate_list("MAY", may_list)

	print ")\n"

#
#  write the aggregate record for an attribute
#
def write_aggregate_attribute(attrib):
	print "attributeTypes: ( %s NAME '%s' SYNTAX '%s' " % (
	       attrib.attributeID, attrib.name, 
	       map_attribute_syntax(attrib.attributeSyntax))
    if attrib['isSingleValued'] == "TRUE":
		print "SINGLE-VALUE "
    if attrib['systemOnly'] == "TRUE":
		print "NO-USER-MODIFICATION "

	print ")\n"


#
#  write the aggregate record
#
def write_aggregate():
	print "dn: CN=Aggregate,${SCHEMADN}\n"
	print """objectClass: top
objectClass: subSchema
objectCategory: CN=SubSchema,${SCHEMADN}
"""
    if not opts.dump_subschema_auto:
		return

    for objectclass in objectclasses:
		write_aggregate_objectclass(objectclass)
    for attr in attributes:
		write_aggregate_attribute(attr)
    for objectclass in objectclasses:
		write_aggregate_ditcontentrule(objectclass)

#
#  load a list from a file
#
def load_list(file):
	var sys = sys_init()
	var s = sys.file_load(file)
	var a = split("\n", s)
	return a

# get the rootDSE
res = ldb.search("", "", ldb.SCOPE_BASE)
rootDse = res[0]

# load the list of classes we are interested in
classes = load_list(classfile)
for (i=0;i<classes.length;i++) {
	var classname = classes[i]
	var class = build_objectclass(ldb, classname)
	if (class != undefined) {
		objectclasses[classname] = class


#
#  expand the objectclass list as needed
#
num_classes = 0
expanded = 0
# calculate the actual number of classes
num_classes = len(objectclasses)

# so EJS do not have while nor the break statement
# cannot find any other way than doing more loops
# than necessary to recursively expand all classes
#
for inf in range(500):
    if expanded < num_classes:
		for (i in objectclasses) {
			var n = objectclasses[i]
			if (objectclasses_expanded[i] != "DONE") {
				expand_objectclass(ldb, objectclasses[i])
				objectclasses_expanded[i] = "DONE"
				expanded++
		# recalculate the actual number of classes
		num_classes = len(objectclasses)

#
#  find objectclass properties
#
for objectclass in objectclasses:
	find_objectclass_properties(ldb, objectclass)


#
#  form the full list of attributes
#
for objectclass in objectclasses:
	add_objectclass_attributes(ldb, objectclass)

# and attribute properties
for attr in attributes:
	find_attribute_properties(ldb, attr)

#
# trim the 'may' attribute lists to those really needed
#
for objectclass in objectclasses) {
	trim_objectclass_attributes(ldb, objectclass)

#
#  dump an ldif form of the attributes and objectclasses
#
if opts.dump_attributes:
	write_ldif(attributes, attrib_attrs)
if opts.dump_classes:
	write_ldif(objectclasses, class_attrs)
if opts.dump_subschema:
	write_aggregate()

if not opts.verbose:
	sys.exit(0)

#
#  dump list of objectclasses
#
print "objectClasses:\n"
for objectclass in objectclasses:
	print "\t%s\n" % objectclass

print "attributes:\n"
for attr in attributes:
	print "\t%s\n" % ttr

print "autocreated attributes:\n"
for (i in attributes) {
	if (attributes[i].autocreate == true) {
		print "\t%s\n" % i
