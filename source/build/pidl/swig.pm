###################################################
# Samba4 parser generator for swig wrappers
# Copyright tpot@samba.org 2004
# released under the GNU GPL

package IdlSwig;

use strict;

# Some build farm machines don't have the Data::Dumper module installed

eval("use Data::Dumper");

my(%interfaces, %functions, %structs, %unions);

sub isunion($)
{
    my($name) = shift;

    return $unions{$name};
}

# Generate code to convert a Python object to an array

sub ArrayFromPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";

    my($size);

    if (util::has_property($e, "size_is")) {
	$size = util::has_property($e, "size_is");
    } else {
	$size = $e->{ARRAY_LEN};
    }

    if (util::has_property($e, "length_is")) {
	$size = util::has_property($e, "length_is");
    }

    if (!util::is_constant($size)) {
	$size = "s->$prefix$size";
    }

    my($type) = $e->{TYPE};

    if (!util::is_scalar_type($type)) {
	$type = "struct $type";
    }

    if (!util::is_constant($e->{ARRAY_LEN})) {
	$result .= "\ts->$prefix$e->{NAME} = talloc(mem_ctx, $size * sizeof($type));\n";
    }

    $result .= "\tif (!PyDict_GetItemString(obj, \"$e->{NAME}\")) {\n";
    $result .= "\t\tPyErr_Format(PyExc_ValueError, \"Expecting key '$e->{NAME}'\");\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\tif (!PyList_Check(PyDict_GetItemString(obj, \"$e->{NAME}\"))) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting list value for key '$e->{NAME}'\");\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\t{\n";

    $result .= "\t\tint i;\n\n";
    $result .= "\t\tfor (i = 0; i < $size; i++) {\n";
    if (util::is_scalar_type($e->{TYPE})) {
	$result .= "\t\t\ts->$prefix$e->{NAME}\[i\] = $e->{TYPE}_from_python(PyList_GetItem(PyDict_GetItemString(obj, \"$e->{NAME}\"), i), \"$e->{NAME}\");\n";
    } else {
	$result .= "\t\t\t$e->{TYPE}_from_python(mem_ctx, &s->$prefix$e->{NAME}\[i\], PyList_GetItem(PyDict_GetItemString(obj, \"$e->{NAME}\"), i), \"$e->{NAME}\");\n";
    }
    $result .= "\t\t}\n";

    $result .= "\t}\n";

    return $result;
}

# Generate code to convert a Python object to a structure field

sub FieldFromPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";
    my($obj) = "PyDict_GetItemString(obj, \"$e->{NAME}\")";

    # Special cases

    if ($e->{TYPE} eq "string") {
	$result .= "\ts->$prefix$e->{NAME} = string_ptr_from_python(mem_ctx, $obj, \"$e->{NAME}\");\n";
	return $result;
    }

    if ($e->{TYPE} eq "DATA_BLOB") {
	if ($e->{POINTERS} == 0) {
	    $result .= "\tDATA_BLOB_from_python(mem_ctx, &s->$prefix$e->{NAME}, $obj, \"$e->{NAME}\");\n";
	} else {
	    $result .= "\tDATA_BLOB_ptr_from_python(mem_ctx, &s->$prefix$e->{NAME}, $obj, \"$e->{NAME}\");\n";
	}
	return $result;
    }

    # Generate conversion for element
    
    if (util::is_scalar_type($e->{TYPE})) {
	
	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		$result .= ArrayFromPython($e, $prefix);
	    } else {
		if (util::has_property($e, "value")) {
		    $result .= "\ts->$prefix$e->{NAME} = 0;\n";
		} else {
		    $result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_from_python($obj, \"$e->{NAME}\");\n";
		}
	    }
	} else {
	    $result .= "\ts->$prefix$e->{NAME} = talloc(mem_ctx, sizeof($e->{TYPE}));\n";
	    $result .= "\t*s->$prefix$e->{NAME} = $e->{TYPE}_from_python($obj, \"$e->{NAME}\");\n";
	}
    } else {
	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		$result .= ArrayFromPython($e, $prefix);
	    } else {
		$result .= "\t$e->{TYPE}_from_python(mem_ctx, &s->$prefix$e->{NAME}, $obj, \"$e->{NAME}\");\n";
	    }
	} else {
	    if ($e->{ARRAY_LEN} or util::has_property($e, "size_is")) {
		$result .= ArrayFromPython($e, $prefix);
	    } else {
		$result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_ptr_from_python(mem_ctx, $obj, \"$e->{NAME}\");\n";
	    }
	}
    }

    return $result;
}

# Generate code to convert an array to a Python object

sub ArrayToPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";

    my($array_len) = util::array_size($e);

    if ($array_len eq "*" or util::has_property($e, "size_is")) {
	$array_len = util::has_property($e, "size_is");
    }

    if (!util::is_constant($array_len)) {
	$array_len = "s->$prefix$array_len";
    }

    my($type) = $e->{TYPE};

    if (!util::is_scalar_type($type)) {
	$type = "struct $type";
    }

    $result .= "\n\t{\n";
    $result .= "\t\tPyObject *temp;\n";
    $result .= "\t\tint i;\n\n";

    $result .= "\t\ttemp = PyList_New($array_len);\n\n";
    $result .= "\t\tfor (i = 0; i < $array_len; i++) {\n";
    if (util::is_scalar_type($e->{TYPE})) {
	$result .= "\t\t\tPyList_SetItem(temp, i, $e->{TYPE}_to_python(s->$prefix$e->{NAME}\[i\]));\n";
    } else {
	$result .= "\t\t\tPyList_SetItem(temp, i, $e->{TYPE}_ptr_to_python(mem_ctx, &s->$prefix$e->{NAME}\[i\]));\n";	
    }
    $result .= "\t\t}\n";

    $result .= "\t\tPyDict_SetItemString(obj, \"$e->{NAME}\", temp);\n";

    $result .= "\t}\n";

    return $result;
}

# Generate code to convert a structure field to a Python object

sub FieldToPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";

    # Special cases

    if ($e->{TYPE} eq "string") {
	$result .= "\tPyDict_SetItemString(obj, \"$e->{NAME}\", string_ptr_to_python(mem_ctx, s->$prefix$e->{NAME}));\n";
	return $result;
    }

    # Generate conversion for scalars and structures

    if (util::is_scalar_type($e->{TYPE})) {
	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		$result .= ArrayToPython($e, $prefix);
	    } else {
		$result .= "\tPyDict_SetItemString(obj, \"$e->{NAME}\", $e->{TYPE}_to_python(s->$prefix$e->{NAME}));\n";
	    }
	} else {
	    if ($e->{ARRAY_LEN} or util::has_property($e, "size_is")) {
		$result .= ArrayToPython($e, $prefix);
	    } else {
		$result .= "\tif (s->$prefix$e->{NAME})\n";
		$result .= "\t\tPyDict_SetItemString(obj, \"$e->{NAME}\", $e->{TYPE}_to_python(*s->$prefix$e->{NAME}));\n";
		$result .= "\telse\n";
		$result .= "\t\tPyDict_SetItemString(obj, \"$e->{NAME}\", Py_None);\n";
	    }
	}
    } else {

	my($extra_args) = "";

	if (isunion($e->{TYPE})) {
	    $extra_args = ", $e->{NAME}_switch_is";
	}

	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		$result .= ArrayToPython($e, $prefix);
	    } else {
		$result .= "\tPyDict_SetItemString(obj, \"$e->{NAME}\", $e->{TYPE}_ptr_to_python(mem_ctx, &s->$prefix$e->{NAME}$extra_args));\n";
	    }
	} else {
	    if ($e->{ARRAY_LEN} or util::has_property($e, "size_is")) {
		$result .= ArrayToPython($e, $prefix);
	    } else {
		$result .= "\tPyDict_SetItemString(obj, \"$e->{NAME}\", $e->{TYPE}_ptr_to_python(mem_ctx, s->$prefix$e->{NAME}$extra_args));\n";
	    }
	}
    }

    return $result;
}

sub ParseFunction($)
{
    my($fn) = shift;
    my($result) = "";

    $result .= "%{\n\n";

    $result .= "/*\n\n";
    $result .= IdlDump::DumpFunction($fn);
    $result .= "*/\n\n";

    # Generate function to convert Python dict to structure pointer

    $result .= "/* Convert Python dict to struct $fn->{NAME}.in */\n\n";

    $result .= "struct $fn->{NAME} *$fn->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj, char *name)\n";
    $result .= "{\n";

    $result .= "\tstruct $fn->{NAME} *s;\n\n";

    $result .= "\tif (!PyDict_Check(obj)) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting dict value for key '%s'\", name);\n";
    $result .= "\t\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\ts = talloc(mem_ctx, sizeof(struct $fn->{NAME}));\n\n";

    # Remove this when all elements are initialised
    $result .= "\tmemset(s, 0, sizeof(struct $fn->{NAME}));\n\n";

    foreach my $e (@{$fn->{DATA}}) {
	if (util::has_property($e, "in")) {
	    if (util::has_property($e, "ref")) {
		$result .= "\tif (PyDict_GetItemString(obj, \"$e->{NAME}\") == Py_None) {\n";
		$result .= "\t\tPyErr_Format(PyExc_ValueError, \"Key '$e->{NAME}' cannot be None\");\n";
		$result .= "\t\treturn NULL;\n";
		$result .= "\t}\n";
	    }
	    $result .= FieldFromPython($e, "in.") ;
	}
    }

    $result .= "\n";
    $result .= "\treturn s;\n";
    $result .= "}\n\n";

    # Generate function to convert structure pointer to Python dict

    $result .= "/* Convert struct $fn->{NAME}.out to Python dict */\n\n";

    $result .= "PyObject *$fn->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, struct $fn->{NAME} *s";

    foreach my $e (@{$fn->{DATA}}) {
	if (isunion($e->{TYPE})) {
	    $result .= ", int $e->{NAME}_switch_is";
	}
    }
    $result .= ")\n";

    $result .= "{\n";

    $result .= "\tPyObject *obj = PyDict_New();\n\n";

    foreach my $e (@{$fn->{DATA}}) {
	$result .= FieldToPython($e, "out.") if util::has_property($e, "out")
    }

    $result .= "\n";
    $result .= "\treturn obj;\n";
    $result .= "}\n\n";

    $result .= "%}\n\n";

    # Input typemap

    $result .= "%typemap(in) struct $fn->{NAME} * {\n";
    $result .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"typemap(int) $fn->{NAME}\");\n\n";

    $result .= "\t\$1 = $fn->{NAME}_ptr_from_python(mem_ctx, \$input, \"<function params>\");\n\n";

    $result .= "\tif (PyErr_Occurred()) return NULL;\n\n";

    $result .= "}\n\n";

    # Output typemap

    $result .= "%typemap(argout) struct $fn->{NAME} * (PyObject *temp) {\n";
    $result .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"typemap(argout) $fn->{NAME}\");\n\n";

    $result .= "\ttemp = $fn->{NAME}_ptr_to_python(mem_ctx, \$1";

    foreach my $e (@{$fn->{DATA}}) {
	if ((my $switch_is = util::has_property($e, "switch_is"))) {
	    $result .= ", \$1->in.$switch_is";
	}
    }

    $result .= ");\n\n";

    if ($fn->{RETURN_TYPE} eq "NTSTATUS") {
	$result .= "\tPyDict_SetItemString(temp, \"result\", resultobj);\n";
    } else {
	$result .= "\tPyDict_SetItemString(temp, \"result\", PyLong_FromLong(W_ERROR_V(arg3->out.result)));\n";
    }

    $result .= "\n";

    $result .= "\tresultobj = temp;\n\n";

    $result .= "\tif (NT_STATUS_IS_ERR(result)) {\n";
    $result .= "\t\tset_ntstatus_exception(NT_STATUS_V(result));\n";
    $result .= "\t\tgoto fail;\n";
    $result .= "\t}\n";

    if (!($fn->{RETURN_TYPE} eq "NTSTATUS")) {
	$result .= "\tif (!W_ERROR_IS_OK(arg3->out.result) && \n";
	$result .= "\t\t!(W_ERROR_EQUAL(arg3->out.result, WERR_INSUFFICIENT_BUFFER)) &&\n";
	$result .= "\t\t!(W_ERROR_EQUAL(arg3->out.result, WERR_NO_MORE_ITEMS)) &&\n";
	$result .= "\t\t!(W_ERROR_EQUAL(arg3->out.result, WERR_MORE_DATA))) {\n";
	$result .= "\t\tset_werror_exception(W_ERROR_V(arg3->out.result));\n";
	$result .= "\t\tgoto fail;\n";
	$result .= "\t}\n";
    }

    $result .= "}\n\n";

    # Function definitions

    $result .= "%rename($fn->{NAME}) dcerpc_$fn->{NAME};\n";
    $result .= "NTSTATUS dcerpc_$fn->{NAME}(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $fn->{NAME} *r);\n\n";

    return $result;
}

sub ParseStruct($)
{
    my($s) = shift;
    my($result) = "";

    $result .= "%{\n\n";

    $result .= "/*\n\n";
    $result .= IdlDump::DumpTypedef($s);
    $result .= "*/\n\n";

    # Generate function to convert Python dict to structure pointer 

    $result .= "/* Convert Python dict to struct $s->{NAME} pointer */\n\n";
    
    $result .= "struct $s->{NAME} *$s->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj, char *name)\n";
    $result .= "{\n";
    $result .= "\tstruct $s->{NAME} *s;\n\n";

    $result .= "\tif (obj == NULL) {\n";
    $result .= "\t\tPyErr_Format(PyExc_ValueError, \"Expecting key '%s'\", name);\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\tif (obj == Py_None) return NULL;\n\n";

    $result .= "\tif (!PyDict_Check(obj)) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting dict value for key '%s'\", name);\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\ts = talloc(mem_ctx, sizeof(struct $s->{NAME}));\n\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$result .= FieldFromPython($e, "");
    }

    $result .= "\n";
    $result .= "\treturn s;\n";
    $result .= "}\n\n";

    # Generate function to convert Python dict to structure

    $result .= "/* Convert Python dict to struct $s->{NAME} */\n\n";
    
    $result .= "void $s->{NAME}_from_python(TALLOC_CTX *mem_ctx, struct $s->{NAME} *s, PyObject *obj, char *name)\n";
    $result .= "{\n";

    $result .= "\tif (obj == NULL) {\n";
    $result .= "\t\tPyErr_Format(PyExc_ValueError, \"Expecting key '%s'\", name);\n";
    $result .= "\t\treturn;\n";
    $result .= "\t}\n\n";

    $result .= "\tif (!PyDict_Check(obj)) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting dict value for key '%s'\", name);\n";
    $result .= "\t\treturn;\n";
    $result .= "\t}\n\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$result .= FieldFromPython($e, "");
    }

    $result .= "}\n\n";

    # Generate function to convert structure pointer to Python dict

    $result .= "/* Convert struct $s->{NAME} pointer to Python dict */\n\n";

    $result .= "PyObject *$s->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, struct $s->{NAME} *s)\n";
    $result .= "{\n";
    
    $result .= "\tPyObject *obj;\n\n";

    $result .= "\tif (s == NULL) {\n";
    $result .= "\t\tPy_INCREF(Py_None);\n";
    $result .= "\t\treturn Py_None;\n";
    $result .= "\t}\n\n";
    
    $result .= "\tobj = PyDict_New();\n\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$result .= FieldToPython($e, "");
    }

    $result .= "\n";
    $result .= "\treturn obj;\n";
    $result .= "}\n\n";

    $result .= "%}\n\n";    

    return $result;
}

sub ParseUnion($)
{
    my($u) = shift;
    my($result) = "";

    $result .= "/*\n\n";
    $result .= IdlDump::DumpTypedef($u);
    $result .= "*/\n\n";

    # Generate function to convert Python dict to union pointer

    $result .= "%{\n\n";
    $result .= "/* Convert Python dict to union $u->{NAME} pointer */\n\n";

    $result .= "union $u->{NAME} *$u->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj, char *name)\n";
    $result .= "{\n";

    $result .= "\tunion $u->{NAME} *u;\n";
    $result .= "\tPyObject *dict;\n\n";
    
    $result .= "\tif (obj == NULL) {\n";
    $result .= "\t\tPyErr_Format(PyExc_ValueError, \"Expecting key '%s'\", name);\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\tif (!PyDict_Check(obj)) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting dict value for key '%s'\", name);\n";
    $result .= "\t\treturn NULL;\n";
    $result .= "\t}\n\n";

    $result .= "\tu = talloc(mem_ctx, sizeof(union $u->{NAME}));\n\n";

    for my $e (@{$u->{DATA}{DATA}}) {
	    if (defined $e->{DATA}{NAME}) {
		    $result .= "\tif ((dict = PyDict_GetItemString(obj, \"$e->{DATA}{NAME}\"))) {\n";
		    if ($e->{DATA}{POINTERS} == 0) {
			    $result .= "\t\t$e->{DATA}{TYPE}_from_python(mem_ctx, &u->$e->{DATA}{NAME}, dict, \"$e->{DATA}{NAME}\");\n";
		    } elsif ($e->{DATA}{POINTERS} == 1) {
			    $result .= "\t\tu->$e->{DATA}{NAME} = $e->{DATA}{TYPE}_ptr_from_python(mem_ctx, dict, \"$e->{DATA}{NAME}\");\n";
		    } else {
			    $result .= "\t\t// $e->{DATA}{TYPE} pointers=$e->{DATA}{POINTERS}\n";
		    }
	    }

	$result .= "\t\treturn u;\n";
	$result .= "\t}\n\n";
    }

    $result .= "\treturn NULL;\n";
    $result .= "}\n\n";

    # Generate function to convert Python dict to union

    $result .= "/* Convert Python dict to union $u->{NAME} */\n\n";

    $result .= "void $u->{NAME}_from_python(TALLOC_CTX *mem_ctx, union $u->{NAME} *u, PyObject *obj, char *name)\n";
    $result .= "{\n";
    $result .= "\tPyObject *dict;\n\n";

    $result .= "\tif (obj == NULL) {\n";
    $result .= "\t\tPyErr_Format(PyExc_ValueError, \"Expecting key '%s'\", name);\n";
    $result .= "\t\treturn;\n";
    $result .= "\t}\n\n";

    $result .= "\tif (!PyDict_Check(obj)) {\n";
    $result .= "\t\tPyErr_Format(PyExc_TypeError, \"Expecting dict value for key '%s'\", name);\n";
    $result .= "\t\treturn;\n";
    $result .= "\t}\n\n";

    for my $e (@{$u->{DATA}{DATA}}) {
	    if (defined $e->{DATA}{NAME}) {
	$result .= "\tif ((dict = PyDict_GetItemString(obj, \"$e->{DATA}{NAME}\"))) {\n";
	if ($e->{DATA}{POINTERS} == 0) {
	    $result .= "\t\t$e->{DATA}{TYPE}_from_python(mem_ctx, &u->$e->{DATA}{NAME}, dict, \"$e->{DATA}{NAME}\");\n";
	} elsif ($e->{DATA}{POINTERS} == 1) {
	    $result .= "\t\tu->$e->{DATA}{NAME} = $e->{DATA}{TYPE}_ptr_from_python(mem_ctx, dict, \"$e->{DATA}{NAME}\");\n";
	} else {
	    $result .= "\t\t// $e->{DATA}{TYPE} pointers=$e->{DATA}{POINTERS}\n";
	}
	}
	$result .= "\t\treturn;\n";
	$result .= "\t}\n\n";
    }
    $result .= "}\n\n";

    # Generate function to convert union pointer to Python dict

    $result .= "/* Convert union $u->{NAME} pointer to Python dict */\n\n";

    $result .= "PyObject *$u->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, union $u->{NAME} *u, int switch_is)\n";
    $result .= "{\n";
    $result .= "\tPyObject *obj;\n\n";

    $result .= "\tif (u == NULL) {\n";
    $result .= "\t\tPy_INCREF(Py_None);\n";
    $result .= "\t\treturn Py_None;\n";
    $result .= "\t}\n\n";

    $result .= "\tobj = PyDict_New();\n\n";

    for my $e (@{$u->{DATA}{DATA}}) {
	$result .= "\tif (switch_is == $e->{CASE}) {\n";
	my $prefix = util::c_pull_prefix($e);
	if (defined $e->{DATA}{NAME}) {
		$result .= "\t\tPyDict_SetItemString(obj, \"$e->{DATA}{NAME}\", $e->{DATA}{TYPE}_ptr_to_python(mem_ctx, ${prefix}u->$e->{DATA}{NAME}));\n";
	}
	$result .= "\t}\n";
    }

    $result .= "\treturn obj;\n";

    $result .= "}\n\n";

    if (util::has_property($u, "public")) {

	# Generate function to unmarshall an array of structures.
	# Used exclusively (?) in the spoolss pipe.

	$result .= "/* Unmarshall an array of structures from a Python string */\n\n";

	$result .= "NTSTATUS unmarshall_$u->{NAME}_array(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, uint32 level, uint32 count, union $u->{NAME} **info)\n";
	$result .= "{\n";
	$result .= "\tint i;\n";
	$result .= "\tstruct ndr_pull *ndr;\n";
	$result .= "\tndr = ndr_pull_init_blob(blob, mem_ctx);\n";
	$result .= "\tif (!ndr) {\n";
	$result .= "\t\treturn NT_STATUS_NO_MEMORY;\n";
	$result .= "\t}\n";
	$result .= "\tNDR_ALLOC_N(ndr, (*info), count);\n";
	$result .= "\tfor (i=0;i<count;i++) {\n";
	$result .= "\t\tndr->data += ndr->offset;\n";
	$result .= "\t\tndr->offset = 0;\n";
	$result .= "\t\tNDR_CHECK(ndr_pull_$u->{NAME}(ndr, NDR_SCALARS|NDR_BUFFERS, level, &(*info)[i]));\n";
	$result .= "\t}\n\n";
	$result .= "\treturn NT_STATUS_OK;\n";
	$result .= "\t}\n";
    }

    $result .= "%}\n\n";    

    if (util::has_property($u, "public")) {

	$result .= "%typemap(in, numinputs=0) union $u->{NAME} **EMPTY (union $u->{NAME} *temp_$u->{NAME}) {\n";
	$result .= "\t\$1 = &temp_$u->{NAME};\n";
	$result .= "}\n\n";

	$result .= "%typemap(argout) (uint32 level, uint32 count, union $u->{NAME} **EMPTY) {\n";
	$result .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"unmarshall_$u->{NAME}_array\");\n";
	$result .= "\tint i;\n\n";
	$result .= "\t\$result = PyList_New(\$2);\n\n";
	$result .= "\tfor (i = 0; i < \$2; i++) {\n";
	$result .= "\t\tPyList_SetItem(\$result, i, $u->{NAME}_ptr_to_python(mem_ctx, &(*\$3)[i], \$1));\n";
	$result .= "\t}\n\n";
	$result .= "\ttalloc_free(mem_ctx);\n";
	$result .= "}\n\n";

	$result .= "NTSTATUS unmarshall_$u->{NAME}_array(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, uint32 level, uint32 count, union $u->{NAME} **EMPTY);\n\n";
    }

    return $result;
}

sub ParseTypedef($)
{
    my($t) = shift;
    my($result) = "";

    foreach my $e ($t) {
	$result .= ParseStruct($e) if $e->{DATA}{TYPE} eq "STRUCT";
	$result .= ParseUnion($e) if $e->{DATA}{TYPE} eq "UNION";
    }

    return $result;
}

sub ParseInheritedData($)
{
    my($data) = shift;
    my($result) = "";

    foreach my $e (@{$data}) {
	$result .= ParseFunction($e) if $e->{TYPE} eq "FUNCTION";
	$result .= ParseTypedef($e) if $e->{TYPE} eq "TYPEDEF";
    }

    return $result;
}

sub ParseHeader($)
{
    my($hdr) = shift;
    my($result) = "";

    if ($hdr->{PROPERTIES}{uuid}) {
	my($name) = $hdr->{NAME};
	$result .= "#define DCERPC_" . uc($name) . "_UUID " . 
	    util::make_str($hdr->{PROPERTIES}->{uuid}) . "\n";
	$result .= "const int DCERPC_" . uc($name) . "_VERSION = " . $hdr->{PROPERTIES}->{version} . ";\n";
	$result .= "#define DCERPC_" . uc($name) . "_NAME \"" . $name . "\"\n";
	$result .= "\n";
    }

    $result .= ParseInheritedData($hdr->{INHERITED_DATA});

    return $result;
}

sub Parse($)
{
    my($idl) = shift;
    my($result) = "";

    # Make index of functions, structs and unions.  Currently unused.

    foreach my $x (@{$idl}) {
	my($iname) = $x->{NAME};
	$interfaces{$iname} = $x->{PROPERTIES};
	foreach my $i (@{$x->{INHERITED_DATA}}) {
	    $functions{$i->{NAME}} = $i if $i->{TYPE} eq "FUNCTION";
	    if ($i->{TYPE} eq "TYPEDEF") {
		$structs{$i->{NAME}} = $i->{DATA} if $i->{DATA}{TYPE} eq "STRUCT";
		$unions{$i->{NAME}} = $i->{DATA} if $i->{DATA}{TYPE} eq "UNION";
	    }
	}
    }

    # Generate interface

    $result .= "/* Auto-generated by pidl. Tastes like -*- C -*-. */\n\n";

    foreach my $x (@{$idl}) {
	$result .= ParseHeader($x) if ($x->{TYPE} eq "INTERFACE");
    }

    return $result;
}

1;
