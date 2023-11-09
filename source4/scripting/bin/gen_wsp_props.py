#!/usr/bin/env python
#
# Unix SMB/CIFS implementation.
#
# WSP property definitions
#
# Copyright (C) Noel Power
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import unicode_literals
import sys, os.path, io, string

# parsed error data

# map of guid to propinfo
GuidToPropMap = {}

# list of property id to name maps
GuidToPropMapLocation = {}

props_read = 0

class PropInfo:
	def __init__(self):
		self.propName = ""
		self.propId = 0
		self.inInvertedIndex = "FALSE"
		self.isColumn = "TRUE"
		self.canColumnBeIndexed = "TRUE"
		self.dataType = None
		self.maxSize = 0
		self.isVectorProp = "FALSE"
		self.description = ""
		self.hasExtraInfo = False

def parseCSV(fileContents, hasExtraInfo):
	global props_read
	lines = 0
	for line in fileContents:
		toParse = line.strip()
		lines = lines + 1

		if toParse[0] == '#':
			continue

		parsed = toParse.split(',',9)
		newProp = PropInfo()
		newProp.hasExtraInfo = hasExtraInfo
		newProp.propName = parsed[0]
		guid = parsed[1].upper()
		newProp.propId = int(parsed[2])

		if len(parsed[3]):
			newProp.inInvertedIndex = parsed[3]
		if len(parsed[4]):
			newProp.isColumn = parsed[4]
		if len(parsed[5]):
			newProp.canColumnBeIndexed = parsed[5]
		if len(parsed[6]):
			newProp.dataType = parsed[6]
		if len(parsed[7]):
			newProp.maxSize = parsed[7]
		if len(parsed[8]):
			newProp.isVectorProp = parsed[8]
		if len(parsed[9]):
			newProp.description = parsed[9]

		if not guid in GuidToPropMap:
			GuidToPropMap[guid] = []

		GuidToPropMap[guid].append(newProp)

		props_read = props_read + 1

def parseGuid(guid):
	noBrackets = guid.split('{')[1].split('}')[0]
	parts = noBrackets.split('-')
	result = "{0x" + parts[0] + ", 0x" + parts[1] + ", 0x" + parts[2]
	result = result + ", {0x" + parts[3][0:2] + ", 0x" + parts[3][2:4] + "}, "
	result = result + "{0x" + parts[4][0:2] + ", 0x" + parts[4][2:4] + ", "
	result = result + "0x" + parts[4][4:6] + ", 0x" + parts[4][6:8] + ", "
	result = result + "0x" + parts[4][8:10] + ", 0x" + parts[4][10:12] + "}"
	result = result + "}"
	return result;

def getBoolString(boolString):
	if boolString  == "TRUE":
		return "true"
	else:
		return "false"

def getVtype(prop):
	result = "Unknown"
	if prop.dataType == "GUID":
		result = "VT_CLSID"
	if prop.dataType == "String":
		result = "VT_LPWSTR"
	if prop.dataType == "BString":
		result = "VT_BSTR"
	elif prop.dataType == "Double":
		result = "VT_R8"
	elif prop.dataType == "Buffer":
		result = "VT_BLOB_OBJECT"
	elif prop.dataType == "Byte":
		result = "VT_UI1"
	elif prop.dataType == "UInt64":
		result = "VT_UI8"
	elif prop.dataType == "Int64":
		result = "VT_I8"
	elif prop.dataType == "UInt32":
		result = "VT_UI4"
	elif prop.dataType == "Int32":
		result = "VT_I4"
	elif prop.dataType == "UInt16":
		result = "VT_UI2"
	elif prop.dataType == "Int16":
		result = "VT_I2"
	elif prop.dataType == "DateTime":
		result = "VT_FILETIME"
	elif prop.dataType == "Boolean":
		result = "VT_BOOL"
	if prop.isVectorProp == "TRUE":
		result = result + " | VT_VECTOR"
	return result

def generateSourceCode(propMap, outputFile):
	source = "#include \"replace.h\"\n"
	source = source + "#include \"bin/default/librpc/gen_ndr/ndr_wsp.h\"\n"
	source = source + "#include \"librpc/wsp/wsp_util.h\"\n"
	count = 0
	for guid in propMap.keys():
		varName = "guid_properties_%d"%count
		GuidToPropMapLocation[guid] = varName
		count = count + 1

		source = source + "static const struct full_propset_info %s[] = {\n"%varName
		for props in propMap[guid]:
			extraInfo = "false"
			if props.hasExtraInfo:
				extraInfo = "true"
			source = source + "\t{0x%x,\"%s\",%s, %s, %s, %s, %s, %s},\n"%(props.propId, props.propName, getVtype(props), extraInfo, getBoolString(props.inInvertedIndex),getBoolString(props.isColumn), getBoolString(props.canColumnBeIndexed), props.maxSize)

		source = source + "\t{0,NULL,0,false,false,false,false,0}\n};\n\n"

	source = source + "\n"

	source = source + "const struct full_guid_propset full_propertyset[] = {\n";
	for guid in propMap.keys():
		guidBytes = parseGuid(guid)
		varName = GuidToPropMapLocation[guid]
		source = source + "\t{" + guidBytes + "," + varName + "},\n"

	source = source + "\t{{0, 0, 0, {0, 0}, {0, 0, 0, 0, 0, 0}}," + "NULL" + "},\n"
	source = source + "};\n"
	outputFile.write(source)

def main ():
	inputFile = None
	outputSrcFile = None
	extraPropsLimitedInfo = None
	if len(sys.argv) > 3:
		inputFile =  sys.argv[1]
		outputFile =  sys.argv[2]
		# this file contains extra properties (that don't have the full
		# set of property information
		if len(sys.argv) > 3:
			extraPropsLimitedInfo = sys.argv[3]
	else:
		print ("usage: %s property-csv outfile optionalLimitedInfoProps"%(sys.argv[0]))
		sys.exit(0)
	fileContents = io.open(inputFile,"rt",  encoding='utf8')
	outputSource = io.open(outputFile,"wt", encoding='utf8')
	parseCSV(fileContents, True)
	fileContents.close()

	if extraPropsLimitedInfo != None:
		fileContents = io.open(extraPropsLimitedInfo,"rt", encoding='utf8')
		parseCSV(fileContents, False)
		fileContents.close()

	generateSourceCode(GuidToPropMap, outputSource)

	outputSource.close()
	print ("ok! parsed %d properties and %d propsets(guid)"%(props_read,len(GuidToPropMap.keys())))


if __name__ == '__main__':

    main()

