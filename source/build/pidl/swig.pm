###################################################
# Samba4 parser generator for swig wrappers
# Copyright tpot@samba.org 2004
# released under the GNU GPL

package IdlSwig;

use strict;
use Data::Dumper;

my($res);
my($name);

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
	$result .= "\ts->$prefix$e->{NAME} = $e->{TYPE}_from_python($obj);\n";
	return $result;
    }

    if ($e->{TYPE} eq "string" && $e->{POINTERS} == 1) {
	$result .= "\ts->$prefix$e->{NAME} = policy_handle_from_python($obj);\n";
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
	# Non-scalar type
	$result .= DebugElement($e);
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
	$result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), policy_handle_to_python(s->$prefix$e->{NAME}));\n";
	return $result;
    }

    if ($e->{TYPE} eq "string" && $e->{POINTERS} == 1) {
	$result .= "\tPyDict_SetItem(obj, PyString_FromString(\"$e->{NAME}\"), string_to_python(s->$prefix$e->{NAME}));\n";
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
	# Non-scalar type
	$result .= DebugElement($e);
    }

    return $result;
}

sub ParseFunction($)
{
    my($fn) = shift;

    $res .= "%{\n\n";

    $res .= "/* Convert Python dict to struct $fn->{NAME}.in */\n\n";

    $res .= "int $fn->{NAME}_from_python(TALLOC_CTX *mem_ctx, struct $fn->{NAME} *s, PyObject *obj)\n";
    $res .= "{\n";

    foreach my $e (@{$fn->{DATA}}) {
	$res .= XFromPython($e, "in.") if util::has_property($e, "in")
    }

    $res .= "\n";
    $res .= "\treturn True;\n";
    $res .= "}\n\n";

    $res .= "/* Convert struct $fn->{NAME}.out to Python dict */\n\n";

    $res .= "int $fn->{NAME}_to_python(TALLOC_CTX *mem_ctx, PyObject *obj, struct $fn->{NAME} *s)\n";
    $res .= "{\n";

    foreach my $e (@{$fn->{DATA}}) {
	$res .= XToPython($e, "out.") if util::has_property($e, "out")
    }

    $res .= "\n";
    $res .= "\treturn True;\n";
    $res .= "}\n\n";

    $res .= "%}\n\n";

    # Input typemap

    $res .= "%typemap(in) struct $fn->{NAME} * (struct $fn->{NAME} temp) {\n";
    $res .= "\tTALLOC_CTX *mem_ctx = talloc_init(\"typemap(int) $fn->{NAME}\");\n\n";
    $res .= "\t$fn->{NAME}_from_python(mem_ctx, &temp, \$input);\n";
    $res .= "\t\$1 = &temp;\n";
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
    $res .= "\tdict = PyDict_New();\n";

    $res .= "\t$fn->{NAME}_to_python(mem_ctx, dict, \$1);\n";

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
    $res .= "/* Convert Python dict to struct $s->{NAME} */\n\n";
    
    $res .= "int python_to_$s->{NAME}(TALLOC_CTX *mem_ctx, struct $s->{NAME} *s, PyObject *obj)\n";
    $res .= "{\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$res .= XFromPython($e, "");
    }

    $res .= "\n";
    $res .= "\treturn TRUE;\n";
    $res .= "}\n\n";

    $res .= "/* Convert struct $s->{NAME} to Python dict */\n\n";

    $res .= "int $s->{NAME}_to_python(TALLOC_CTX *mem_ctx, PyObject *obj, struct $s->{NAME} *s)\n";
    $res .= "{\n";

    foreach my $e (@{$s->{DATA}{ELEMENTS}}) {
	$res .= XToPython($e, "");
    }

    $res .= "\n";
    $res .= "\treturn TRUE;\n";
    $res .= "}\n";

    $res .= "\n%}\n\n";    
}

sub ParseTypedef($)
{
    my($t) = shift;

    foreach my $e ($t) {
	($e->{DATA}{TYPE} eq "STRUCT") && ParseStruct($e);
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

    $res = "/* auto-generated by pidl */\n\n";

    foreach my $x (@{$idl}) {
	($x->{TYPE} eq "INTERFACE") && ParseHeader($x);
    }

    return $res;
}

1;
