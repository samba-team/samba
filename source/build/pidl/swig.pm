###################################################
# Samba4 parser generator for swig wrappers
# Copyright tpot@samba.org 2004
# released under the GNU GPL

package IdlSwig;

use strict;

eval("use Data::Dumper");

my(%interfaces, %functions, %structs, %unions);
my($res, $name);

sub DebugElement($)
{
    my($e) = shift;
    my($result) = "";

    $result .= "\t// $e->{TYPE} $e->{NAME} ";

    $result .= "(scalar) " 
	if util::is_scalar_type($e->{TYPE});

    $result .= "pointers=$e->{POINTERS} " 
	if $e->{POINTERS} > 0;

    my($size_is) = util::has_property($e, "size_is");
    $result .= "size_is=" . $size_is . " " if $size_is;

    my($length_is) = util::has_property($e, "length_is");
    $result .= "length_is=" . $length_is . " " if $length_is;

    $result .= "array_len=" . $e->{ARRAY_LEN} . " " if $e->{ARRAY_LEN};

    $result .= "\n";

    return $result;
}

sub XFromPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";
    my($obj) = "PyDict_GetItem(obj, PyString_FromString(\"$e->{NAME}\"))";

    # Special cases

    if (($e->{TYPE} eq "policy_handle" || $e->{TYPE} eq "string") && $e->{POINTERS} == 1) {
	$result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_ptr_from_python(mem_ctx, $obj);\n";
	return $result;
    }

    if ($e->{TYPE} eq "string" && $e->{POINTERS} == 1) {
	$result .= "\ts->$prefix$e->{NAME} = policy_handle_ptr_from_python(mem_ctx, $obj);\n";
	return $result;
    }

    # Generate conversion for element
    
    if (util::is_scalar_type($e->{TYPE})) {
	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		# pointer to scalar with array len property
		$result .= DebugElement($e);
	    } else {
		$result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_from_python($obj);\n";
	    }
	} else {
	    # Pointer to scalar
	    $result .= DebugElement($e);
	}
    } else {
	if ($e->{POINTERS} == 0) {
	    # Non-scalar type, no pointer
	    $result .= DebugElement($e);
	} elsif ($e->{POINTERS} == 1) {
	    $result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_ptr_from_python(mem_ctx, $obj);\n";
	} else {
	    # Non-scalar type, multiple pointers
	    $result .= DebugElement($e);
	}
    }

    return $result;
}

sub XToPython($$)
{
    my($e) = shift;
    my($prefix) = shift;
    my($result) = "";

    # Special cases

    if ($e->{TYPE} eq "policy_handle" && $e->{POINTERS} == 1) {
	$result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), policy_handle_ptr_to_python(mem_ctx, s->$prefix$e->{NAME}));\n";
	return $result;
    }

    if ($e->{TYPE} eq "string" && $e->{POINTERS} == 1) {
	$result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), string_ptr_to_python(mem_ctx, s->$prefix$e->{NAME}));\n";
	return $result;
    }

    # Generate conversion for element

    if (util::is_scalar_type($e->{TYPE})) {
	if ($e->{POINTERS} == 0) {
	    if ($e->{ARRAY_LEN}) {
		# pointer to scalar with array len property
		$result .= DebugElement($e);
	    } else {
		$result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), $e->{TYPE}_to_python(s->$prefix$e->{NAME}));\n";
	    }
	} else {
	    # Pointer to scalar
	    $result .= DebugElement($e);
	}
    } else {
	if ($e->{POINTERS} == 0) {
	    # Non-scalar type, no pointer
	    $result .= DebugElement($e);
	} elsif ($e->{POINTERS} == 1) {
	    $result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), $e->{TYPE}_ptr_to_python(mem_ctx, s->$prefix$e->{NAME}));\n";
	} else {
	    # Non-scalar type, multiple pointers
	    $result .= DebugElement($e);
	}
    }

    return $result;
}

sub ParseFunction($)
{
    my($fn) = shift;

    $res .= "%{\n\n";

    $res .= "/* Convert Python dict to struct $fn->{NAME}.in */\n\n";

    $res .= "struct $fn->{NAME} *$fn->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)\n";
    $res .= "{\n";

    $res .= "\tstruct $fn->{NAME} *s = talloc(mem_ctx, sizeof(struct $fn->{NAME}));\n\n";

    # Remove this when all elements are initialised
    $res .= "\tmemset(s, 0, sizeof(struct $fn->{NAME}));\n\n";

    foreach my $e (@{$fn->{DATA}}) {
	$res .= XFromPython($e, "in.") if util::has_property($e, "in")
    }

    $res .= "\n";
    $res .= "\treturn s;\n";
    $res .= "}\n\n";

    $res .= "/* Convert struct $fn->{NAME}.out to Python dict */\n\n";

    $res .= "PyObject *$fn->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, struct $fn->{NAME} *s)\n";
    $res .= "{\n";

    $res .= "\tPyObject *obj = PyDict_New();\n\n";

    foreach my $e (@{$fn->{DATA}}) {
	$res .= XToPython($e, "out.") if util::has_property($e, "out")
    }

    $res .= "\n";
    $res .= "\treturn obj;\n";
    $res .= "}\n\n";

    $res .= "%}\n\n";

    # Input typemap

    $res .= "%typemap(in) struct $fn->{NAME} * {\n";
    $res .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"typemap(int) $fn->{NAME}\");\n\n";
    $res .= "\t\$1 = $fn->{NAME}_ptr_from_python(mem_ctx, \$input);\n";
    $res .= "}\n\n";

    # Output typemap

    $res .= "%typemap(argout) struct $fn->{NAME} * {\n";
    $res .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"typemap(argout) $fn->{NAME}\");\n\n";
    $res .= "\tlong status = PyLong_AsLong(resultobj);\n";
    $res .= "\tPyObject *dict;\n";
    $res .= "\n";
    $res .= "\tif (status != 0) {\n";
    $res .= "\t\tset_ntstatus_exception(status);\n";
    $res .= "\t\treturn NULL;\n";
    $res .= "\t}\n";
    $res .= "\n";
    $res .= "\tdict = $fn->{NAME}_ptr_to_python(mem_ctx, \$1);\n";

    $res .= "\tresultobj = dict;\n";
    $res .= "}\n\n";

    # Function definitions

    $res .= "%rename($fn->{NAME}) dcerpc_$fn->{NAME};\n";
    $res .= "$fn->{RETURN_TYPE} dcerpc_$fn->{NAME}(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct $fn->{NAME} *r);\n\n";
}

sub ParseStruct($)
{
    my($s) = shift;

    $res .= "%{\n\n";
    $res .= "/* Convert Python dict to struct $s->{NAME} pointer */\n\n";
    
    $res .= "struct $s->{NAME} *$s->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)\n";
    $res .= "{\n";
    $res .= "\tstruct $s->{NAME} *s = talloc(mem_ctx, sizeof(struct $s->{NAME}));\n\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$res .= XFromPython($e, "");
    }

    $res .= "\n";
    $res .= "\treturn s;\n";
    $res .= "}\n\n";

    $res .= "/* Convert Python dict to struct $s->{NAME} */\n\n";
    
    $res .= "void $s->{NAME}_from_python(TALLOC_CTX *mem_ctx, struct $s->{NAME} *s, PyObject *obj)\n";
    $res .= "{\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$res .= XFromPython($e, "");
    }

    $res .= "}\n\n";

    $res .= "/* Convert struct $s->{NAME} to Python dict */\n\n";

    $res .= "PyObject *$s->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, struct $s->{NAME} *s)\n";
    $res .= "{\n";
    
    $res .= "\tPyObject *obj = PyDict_New();\n\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$res .= XToPython($e, "");
    }

    $res .= "\n";
    $res .= "\treturn obj;\n";
    $res .= "}\n";

    $res .= "\n%}\n\n";    
}

sub ParseUnion($)
{
    my($u) = shift;

    $res .= "%{\n\n";
    $res .= "/* Convert Python dict to union $u->{NAME} */\n\n";

    $res .= "union $u->{NAME} *$u->{NAME}_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)\n";
    $res .= "{\n";

    $res .= "\tunion $u->{NAME} *u = talloc(mem_ctx, sizeof(union $u->{NAME}));\n";
    $res .= "\tPyObject *dict;\n\n";

    
    for my $e (@{$u->{DATA}{DATA}}) {
	$res .= "\tif ((dict = PyDict_GetItem(obj, PyString_FromString(\"$e->{DATA}{NAME}\")))) {\n";
	if ($e->{DATA}{POINTERS} == 0) {
	    $res .= "\t\t$e->{DATA}{TYPE}_from_python(mem_ctx, &u->$e->{DATA}{NAME}, dict);\n";
	} elsif ($e->{DATA}{POINTERS} == 1) {
	    $res .= "\t\tu->$e->{DATA}{NAME} = $e->{DATA}{TYPE}_ptr_from_python(mem_ctx, dict);\n";
	} else {
	    $res .= "\t\t// $e->{DATA}{TYPE} pointers=$e->{DATA}{POINTERS}\n";
	}

	$res .= "\t\treturn u;\n";
	$res .= "\t}\n\n";
    }

    $res .= "\treturn NULL;\n";
    $res .= "}\n\n";

    $res .= "/* Convert union $u->{NAME} to Python dict */\n\n";

    $res .= "PyObject *$u->{NAME}_ptr_to_python(TALLOC_CTX *mem_ctx, union $u->{NAME} *u)\n";
    $res .= "{\n";
    $res .= "\treturn PyDict_New();\n";
    $res .= "}\n\n";

    $res .= "\n%}\n\n";    
}

sub ParseTypedef($)
{
    my($t) = shift;

    foreach my $e ($t) {
	($e->{DATA}{TYPE} eq "STRUCT") && ParseStruct($e);
	($e->{DATA}{TYPE} eq "UNION") && ParseUnion($e);
    }
}

sub ParseInheritedData($)
{
    my($data) = shift;

    foreach my $e (@{$data}) {
	($e->{TYPE} eq "FUNCTION") && ParseFunction($e);
	($e->{TYPE} eq "TYPEDEF") && ParseTypedef($e);
    }
}

sub ParseHeader($)
{
    my($hdr) = shift;

    $name = $hdr->{NAME};
    $res .= "#define DCERPC_" . uc($name) . "_UUID \"$hdr->{PROPERTIES}->{uuid}\"\n";
    $res .= "const int DCERPC_" . uc($name) . "_VERSION = " . $hdr->{PROPERTIES}->{version} . ";\n";
    $res .= "#define DCERPC_" . uc($name) . "_NAME \"" . $name . "\"\n";
    $res .= "\n";

    ParseInheritedData($hdr->{INHERITED_DATA});    
}

sub Parse($)
{
    my($idl) = shift;

    # Make index of functions, structs and unions

    %interfaces = ();
    %functions = ();
    %structs = ();
    %unions = ();

    foreach my $x (@{$idl}) {
	my($iname) = $x->{NAME};
	$interfaces{$iname} = $x->{PROPERTIES};
	foreach my $i (@{$x->{INHERITED_DATA}}) {
	    $functions{$iname}{$i->{NAME}} = $i if $i->{TYPE} eq "FUNCTION";
	    if ($i->{TYPE} eq "TYPEDEF") {
		$structs{$iname}{$i->{NAME}} = $i->{DATA} if $i->{DATA}{TYPE} eq "STRUCT";
		$unions{$iname}{$i->{NAME}} = $i->{DATA} if $i->{DATA}{TYPE} eq "UNION";
	    }
	}
    }

    # Generate interface

    $res = "/* auto-generated by pidl */\n\n";

    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "INTERFACE") && ParseHeader($x);
    }

    return $res;
}

1;
