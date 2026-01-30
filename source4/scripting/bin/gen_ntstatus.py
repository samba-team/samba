#!/usr/bin/env python3

#
# Unix SMB/CIFS implementation.
#
# HRESULT Error definitions
#
# Copyright (C) Noel Power <noel.power@suse.com> 2014
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

import sys, io
from gen_error_common import ErrorDef, parseErrorDescriptions

def generateHeaderFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n\n")
    out_file.write("#ifndef _NTSTATUS_GEN_H\n")
    out_file.write("#define _NTSTATUS_GEN_H\n")
    for err in errors:
        line = "#define %s NT_STATUS(%#x)\n" % (err.err_define, err.err_code)
        out_file.write(line)
    out_file.write("\n#endif /* _NTSTATUS_GEN_H */\n")

def generateSourceFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Names for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")

    out_file.write("static const nt_err_code_struct nt_errs[] = \n")
    out_file.write("{\n")
    for err in errors:
        out_file.write("\t{ \"%s\", %s },\n" % (err.err_define, err.err_define))
    out_file.write("{ 0, NT_STATUS(0) }\n")
    out_file.write("};\n")

    out_file.write("\n/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")

    out_file.write("static const nt_err_code_struct nt_err_desc[] = \n")
    out_file.write("{\n")
    for err in errors:
        # Account for the possibility that some errors may not have descriptions
        if err.err_string == "":
            continue
        out_file.write("\t{ N_(\"%s\"), %s },\n"%(err.err_string, err.err_define))
    out_file.write("{ 0, NT_STATUS(0) }\n")
    out_file.write("};")

def generatePythonFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * New descriptions for existing errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n")
    out_file.write("#include \"lib/replace/system/python.h\"\n")
    out_file.write("#include \"python/py3compat.h\"\n")
    out_file.write("#include \"includes.h\"\n\n")
    out_file.write("static struct PyModuleDef moduledef = {\n")
    out_file.write("\tPyModuleDef_HEAD_INIT,\n")
    out_file.write("\t.m_name = \"ntstatus\",\n")
    out_file.write("\t.m_doc = \"NTSTATUS error defines\",\n")
    out_file.write("\t.m_size = -1,\n")
    out_file.write("};\n\n")
    out_file.write("static void py_addstr(PyObject *m, NTSTATUS status, const char *name)\n");
    out_file.write("{\n");
    out_file.write("\tPyObject *num = PyLong_FromUnsignedLongLong(NT_STATUS_V(status));\n");
    out_file.write("\tPyModule_AddObject(m, name, num);\n");
    out_file.write("}\n\n");
    out_file.write("MODULE_INIT_FUNC(ntstatus)\n")
    out_file.write("{\n")
    out_file.write("\tPyObject *m;\n\n")
    out_file.write("\tm = PyModule_Create(&moduledef);\n")
    out_file.write("\tif (m == NULL)\n")
    out_file.write("\t\treturn NULL;\n\n")
    for err in errors:
        out_file.write(f"\tpy_addstr(m, {err.err_define}, \"{err.err_define}\");\n")
    out_file.write("\n")
    out_file.write("\treturn m;\n")
    out_file.write("}\n")


def generateRustFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] http://msdn.microsoft.com/en-us/library/cc704588.aspx\n")
    out_file.write(" */\n\n")
    out_file.write("use std::fmt;\n\n")
    out_file.write("#[derive(PartialEq, Eq)]\n")
    out_file.write("pub struct NTSTATUS(u32);\n\n")
    for err in errors:
        if err.err_define in ['NT_STATUS_OK', 'NT_STATUS_WAIT_0',
                              'NT_STATUS_ABANDONED_WAIT_0',
                              'NT_STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS']:
            out_file.write("#[allow(dead_code)]\n")
        line = "pub const %s: NTSTATUS = NTSTATUS(%#x);\n" % (err.err_define, err.err_code)
        out_file.write(line)
    out_file.write("\nimpl NTSTATUS {\n")
    out_file.write("\tfn description(&self) -> &str {\n")
    out_file.write("\t\tmatch *self {\n")
    for err in errors:
        # Account for the possibility that some errors may not have descriptions
        if err.err_string == "":
            continue
        if err.err_define not in ['NT_STATUS_OK', 'NT_STATUS_WAIT_0',
                                  'NT_STATUS_ABANDONED_WAIT_0',
                                  'NT_STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS']:
            out_file.write("\t\t\t%s => \"%s\",\n" % (err.err_define, err.err_string))
    out_file.write("\t\t\t_ => \"Unknown NTSTATUS error code\",\n")
    out_file.write("\t\t}\n");
    out_file.write("\t}\n");
    out_file.write("}\n\n");
    out_file.write("impl fmt::Display for NTSTATUS {\n")
    out_file.write("\tfn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n")
    out_file.write("\t\twrite!(f, \"NTSTATUS({:#x}): {}\", self.0, self.description())\n")
    out_file.write("\t}\n")
    out_file.write("}\n\n");
    out_file.write("impl fmt::Debug for NTSTATUS {\n")
    out_file.write("\tfn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n")
    out_file.write("\t\twrite!(f, \"NTSTATUS({:#x})\", self.0)\n")
    out_file.write("\t}\n")
    out_file.write("}\n\n");
    out_file.write("impl std::error::Error for NTSTATUS {}\n")

def transformErrorName( error_name ):
    if error_name.startswith("STATUS_"):
        error_name = error_name.replace("STATUS_", "", 1)
    elif error_name.startswith("RPC_NT_"):
        error_name = error_name.replace("RPC_NT_", "RPC_", 1)
    elif error_name.startswith("EPT_NT_"):
        error_name = error_name.replace("EPT_NT_", "EPT_", 1)
    return "NT_STATUS_" + error_name

# Very simple script to generate files nterr_gen.c & ntstatus_gen.h.
# These files contain generated definitions.
# This script takes four inputs:
# [1]: The name of the text file which is the content of an HTML table
#      (e.g. the one found at http://msdn.microsoft.com/en-us/library/cc231200.aspx)
#      copied and pasted.
# [2]: The name of the output generated header file with NTStatus #defines
# [3]: The name of the output generated source file with C arrays
# [4]: The name of the output generated python file
def main ():
    input_file = None

    if len(sys.argv) == 6:
        input_file =  sys.argv[1]
        gen_headerfile_name = sys.argv[2]
        gen_sourcefile_name = sys.argv[3]
        gen_pythonfile_name = sys.argv[4]
        gen_rustfile_name = sys.argv[5]
    else:
        print("usage: %s winerrorfile headerfile sourcefile pythonfile rustfile" % (sys.argv[0]))
        sys.exit()

    # read in the data
    with io.open(input_file, "rt", encoding='utf8') as file_contents:
        errors = parseErrorDescriptions(file_contents, False, transformErrorName)

    # NT_STATUS_OK is a synonym of NT_STATUS_SUCCESS, and is very widely used
    # throughout Samba. It must go first in the list to ensure that to ensure
    # that code that previously found this error code in ‘special_errs’
    # maintains the same behaviour by falling back to ‘nt_errs’.
    ok_status = ErrorDef()
    ok_status.err_code = 0
    ok_status.err_define = 'NT_STATUS_OK'
    errors.insert(0, ok_status)

    print("writing new header file: %s" % gen_headerfile_name)
    out_file = io.open(gen_headerfile_name, "wt", encoding='utf8')
    generateHeaderFile(out_file, errors)
    out_file.close()
    print("writing new source file: %s" % gen_sourcefile_name)
    out_file = io.open(gen_sourcefile_name, "wt", encoding='utf8')
    generateSourceFile(out_file, errors)
    out_file.close()
    print("writing new python file: %s" % gen_pythonfile_name)
    out_file = io.open(gen_pythonfile_name, "wt", encoding='utf8')
    generatePythonFile(out_file, errors)
    out_file.close()
    print("writing new rust file: %s" % gen_rustfile_name)
    out_file = io.open(gen_rustfile_name, "wt", encoding='utf8')
    generateRustFile(out_file, errors)
    out_file.close()

if __name__ == '__main__':

    main()
