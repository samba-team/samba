###################################################
# Python function wrapper generator
# Copyright jelmer@samba.org 2007-2008
# released under the GNU GPL

package Parse::Pidl::Samba4::Python;

use Exporter;
@ISA = qw(Exporter);

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapTypeName expandAlias);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred is_charset_array);
use Parse::Pidl::CUtil qw(get_value_of get_pointer_to);
use Parse::Pidl::Samba4::Header qw(GenerateFunctionInEnv GenerateFunctionOutEnv EnvSubstituteValue GenerateStructEnv);

use vars qw($VERSION);
$VERSION = '0.01';

sub new($) {
	my ($class) = @_;
	my $self = { res => "", res_hdr => "", tabs => "", constants => {},
	             module_methods => []};
	bless($self, $class);
}

sub pidl_hdr ($$)
{
	my $self = shift;
	$self->{res_hdr} .= shift;
}

sub pidl($$)
{
	my ($self, $d) = @_;
	if ($d) {
		$self->{res} .= $self->{tabs};
		$self->{res} .= $d;
	}
	$self->{res} .= "\n";
}

sub indent($)
{
	my ($self) = @_;
	$self->{tabs} .= "\t";
}

sub deindent($)
{
	my ($self) = @_;
	$self->{tabs} = substr($self->{tabs}, 0, -1);
}

sub Import
{
	my $self = shift;
	my @imports = @_;
	foreach (@imports) {
		s/\.idl\"$//;
		s/^\"//;
		$self->pidl_hdr("#include \"librpc/gen_ndr/py_$_\.h\"\n");
	}
}

sub Const($$)
{
    my ($self, $const) = @_;
	$self->register_constant($const->{NAME}, $const->{DTYPE}, $const->{VALUE});
}

sub register_constant($$$$)
{
	my ($self, $name, $type, $value) = @_;

	$self->{constants}->{$name} = [$type, $value];
}

sub EnumAndBitmapConsts($$$)
{
	my ($self, $name, $d) = @_;

	return unless (defined($d->{ELEMENTS}));

	foreach my $e (@{$d->{ELEMENTS}}) {
		$e =~ /^([A-Za-z0-9_]+)=(.*)$/;
		my $cname = $1;
		
		$self->register_constant($cname, $d, $cname);
	}
}

sub FromUnionToPythonFunction($$$)
{
	my ($self, $type, $switch, $name) = @_;

	$self->pidl("PyObject *ret;");
	$self->pidl("");

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		if (defined($e->{CASE})) {
			$self->pidl("$e->{CASE}:");
		} else {
			$self->pidl("default:");
		}

		$self->indent;

		if ($e->{NAME}) {
			$self->ConvertObjectToPython({}, $e, "$name->$e->{NAME}", "ret");
		} else {
			$self->pidl("ret = Py_None;");
		}

		$self->pidl("return ret;");
		$self->pidl("");

		$self->deindent;
	}

	$self->deindent;
	$self->pidl("}");

	$self->pidl("PyErr_SetString(PyExc_TypeError, \"unknown union level\");");
	$self->pidl("return NULL;");
}

sub FromPythonToUnionFunction($$$$$)
{
	my ($self, $type, $typename, $switch, $mem_ctx, $name) = @_;

	my $has_default = 0;

	$self->pidl("$typename *ret = talloc_zero($mem_ctx, $typename);");

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		if (defined($e->{CASE})) {
			$self->pidl("$e->{CASE}:");
		} else {
			$has_default = 1;
			$self->pidl("default:");
		}
		$self->indent;
		if ($e->{NAME}) {
			$self->ConvertObjectFromPython({}, $mem_ctx, $e, $name, "ret->$e->{NAME}", "talloc_free(ret); return NULL;");
		}
		$self->pidl("break;");
		$self->deindent;
		$self->pidl("");
	}

	if (!$has_default) {
		$self->pidl("default:");
		$self->indent;
		$self->pidl("PyErr_SetString(PyExc_TypeError, \"invalid union level value\");");
		$self->pidl("talloc_free(ret);");
		$self->pidl("ret = NULL;");
		$self->deindent;
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("return ret;");
}

sub PythonStruct($$$$)
{
	my ($self, $name, $cname, $d) = @_;

	my $env = GenerateStructEnv($d, "object");

	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_getattr(PyObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *object = py_talloc_get_type(obj, $cname);");
	foreach my $e (@{$d->{ELEMENTS}}) {
		$self->pidl("if (!strcmp(name, \"$e->{NAME}\")) {");
		my $varname = "object->$e->{NAME}";
		$self->indent;
		$self->pidl("PyObject *py_$e->{NAME};");
		$self->ConvertObjectToPython($env, $e, $varname, "py_$e->{NAME}");
		$self->pidl("return py_$e->{NAME};");
		$self->deindent;
		$self->pidl("}");
	}
	$self->pidl("PyErr_SetString(PyExc_AttributeError, \"no such attribute\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static int py_$name\_setattr(PyObject *py_obj, char *name, PyObject *value)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *object = py_talloc_get_type(py_obj, $cname);");
	my $mem_ctx = "py_talloc_get_mem_ctx(py_obj)";
	foreach my $e (@{$d->{ELEMENTS}}) {
		$self->pidl("if (!strcmp(name, \"$e->{NAME}\")) {");
		my $varname = "object->$e->{NAME}";
		$self->indent;
		if ($e->{ORIGINAL}->{POINTERS} > 0) {
			$self->pidl("talloc_free($varname);");
		}
		$self->ConvertObjectFromPython($env, $mem_ctx, $e, "value", $varname, "return -1;");
		$self->pidl("return 0;");
		$self->deindent;
		$self->pidl("}");
	}
	$self->pidl("PyErr_SetString(PyExc_AttributeError, \"no such attribute\");");
	$self->pidl("return -1;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl_hdr("PyAPI_DATA(PyTypeObject) $name\_Type;\n");
	$self->pidl_hdr("#define $name\_Check(op) PyObject_TypeCheck(op, &$name\_Type)\n");
	$self->pidl_hdr("#define $name\_CheckExact(op) ((op)->ob_type == &$name\_Type)\n");
	$self->pidl_hdr("\n");
	$self->pidl("PyTypeObject $name\_Type = {");
	$self->indent;
	$self->pidl("PyObject_HEAD_INIT(NULL) 0,");
	$self->pidl(".tp_name = \"$name\",");
	$self->pidl(".tp_basicsize = sizeof(py_talloc_Object),");
	$self->pidl(".tp_dealloc = py_talloc_dealloc,");
	$self->pidl(".tp_getattr = py_$name\_getattr,");
	$self->pidl(".tp_setattr = py_$name\_setattr,");
	$self->pidl(".tp_repr = py_talloc_default_repr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	my $py_fnname = "py_$name";
	$self->pidl("static PyObject *$py_fnname(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *ret = talloc_zero(NULL, $cname);");
	$self->pidl("return py_talloc_import(&$name\_Type, ret);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	return $py_fnname;
}

sub PythonFunction($$$)
{
	my ($self, $fn, $iface) = @_;

	$self->pidl("static PyObject *py_$fn->{NAME}(PyObject *self, PyObject *args, PyObject *kwargs)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$iface\_InterfaceObject *iface = ($iface\_InterfaceObject *)self;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("TALLOC_CTX *mem_ctx = talloc_new(NULL);");
	$self->pidl("struct $fn->{NAME} r;");
	$self->pidl("PyObject *result;");

	my $env = GenerateFunctionInEnv($fn, "r.");
	my $result_size = 0;

	my $args_format = "";
	my $args_string = "";
	my $args_names = "";

	foreach my $e (@{$fn->{ELEMENTS}}) {
		$self->pidl("PyObject *py_$e->{NAME};");
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$result_size++;
		}
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$args_format .= "O";
			$args_string .= ", &py_$e->{NAME}";
			$args_names .= "\"$e->{NAME}\", ";
		}
	}
	$self->pidl("const char *kwnames[] = {");
	$self->indent;
	$self->pidl($args_names . "NULL");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");
	$self->pidl("if (!PyArg_ParseTupleAndKeywords(args, kwargs, \"$args_format:$fn->{NAME}\", discard_const_p(char *, kwnames)$args_string)) {");
	$self->indent;
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");

	if ($result_size > 0) {
		$self->pidl("");
		$self->pidl("ZERO_STRUCT(r.out);");
	}
	if ($fn->{RETURN_TYPE}) {
		$result_size++;
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->ConvertObjectFromPython($env, "mem_ctx", $e, "py_$e->{NAME}", "r.in.$e->{NAME}", "talloc_free(mem_ctx); return NULL;");
		}
	}
	$self->pidl("status = dcerpc_$fn->{NAME}(iface->pipe, mem_ctx, &r);");
	$self->handle_ntstatus("status", "NULL", "mem_ctx");

	$self->pidl("result = PyTuple_New($result_size);");

	$env = GenerateFunctionOutEnv($fn, "r.");
	my $i = 0;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->ConvertObjectToPython($env, $e, "r.out.$e->{NAME}", "py_$e->{NAME}");
			$self->pidl("PyTuple_SetItem(result, $i, py_$e->{NAME});");
			$i++;
		}
	}

	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("PyTuple_SetItem(result, $i, " . $self->ConvertObjectToPythonData($fn->{RETURN_TYPE}, "r.out.result") . ");");
	}

	$self->pidl("talloc_free(mem_ctx);");
	$self->pidl("return result;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub handle_ntstatus($$$$)
{
	my ($self, $var, $retval, $mem_ctx) = @_;

	$self->pidl("if (NT_STATUS_IS_ERR($var)) {");
	$self->indent;
	$self->pidl("PyErr_SetString(PyExc_RuntimeError, nt_errstr($var));");
	$self->pidl("talloc_free($mem_ctx);") if ($mem_ctx);
	$self->pidl("return $retval;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub PythonType($$$)
{
	my ($self, $d, $interface, $basename) = @_;

	my $actual_ctype = $d;
	if ($actual_ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $actual_ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "STRUCT") {
		my $py_fnname;
		if ($d->{TYPE} eq "STRUCT") {
			$py_fnname = $self->PythonStruct($d->{NAME}, mapTypeName($d), $d);
		} else {
			$py_fnname = $self->PythonStruct($d->{NAME}, mapTypeName($d), $d->{DATA});
		}

		my $fn_name = $d->{NAME};

		$fn_name =~ s/^$interface->{NAME}_//;
		$fn_name =~ s/^$basename\_//;

		$self->register_module_method($fn_name, $py_fnname, "METH_NOARGS", "NULL");
	}

	if ($d->{TYPE} eq "ENUM" or $d->{TYPE} eq "BITMAP") {
		$self->EnumAndBitmapConsts($d->{NAME}, $d);
	}

	if ($d->{TYPE} eq "TYPEDEF" and ($d->{DATA}->{TYPE} eq "ENUM" or $d->{DATA}->{TYPE} eq "BITMAP")) {
		$self->EnumAndBitmapConsts($d->{NAME}, $d->{DATA});
	}

	if ($actual_ctype->{TYPE} eq "UNION") {
		$self->pidl("PyObject *py_import_$d->{NAME}(int level, " .mapTypeName($d) . " *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromUnionToPythonFunction($actual_ctype, "level", "in") if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl(mapTypeName($d) . " *py_export_$d->{NAME}(TALLOC_CTX *mem_ctx, int level, PyObject *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromPythonToUnionFunction($actual_ctype, mapTypeName($d), "level", "mem_ctx", "in") if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
	}
}

sub Interface($$$)
{
	my($self,$interface,$basename) = @_;

	$self->pidl_hdr("#ifndef _HEADER_PYTHON_$interface->{NAME}\n");
	$self->pidl_hdr("#define _HEADER_PYTHON_$interface->{NAME}\n\n");

	$self->pidl_hdr("\n");

	$self->Const($_) foreach (@{$interface->{CONSTS}});

	foreach my $d (@{$interface->{TYPES}}) {
		next if has_property($d, "nopython");

		$self->PythonType($d, $interface, $basename);
	}

	$self->pidl_hdr("PyAPI_DATA(PyTypeObject) $interface->{NAME}_InterfaceType;\n");
	$self->pidl("typedef struct {");
	$self->indent;
	$self->pidl("PyObject_HEAD");
	$self->pidl("struct dcerpc_pipe *pipe;");
	$self->deindent;
	$self->pidl("} $interface->{NAME}_InterfaceObject;");

	$self->pidl("");

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		next if has_property($d, "nopython");

		$self->PythonFunction($d, $interface->{NAME});
	}

	$self->pidl("static PyMethodDef interface_$interface->{NAME}\_methods[] = {");
	$self->indent;
	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		next if has_property($d, "nopython");

		my $fn_name = $d->{NAME};

		$fn_name =~ s/^$interface->{NAME}_//;

		$self->pidl("{ \"$fn_name\", (PyCFunction)py_$d->{NAME}, METH_VARARGS|METH_KEYWORDS, NULL },");
	}
	$self->pidl("{ NULL, NULL, 0, NULL }");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static void interface_$interface->{NAME}_dealloc(PyObject* self)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$interface->{NAME}_InterfaceObject *interface = ($interface->{NAME}_InterfaceObject *)self;");
	$self->pidl("talloc_free(interface->pipe);");
	$self->pidl("PyObject_Del(self);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *interface_$interface->{NAME}_getattr(PyObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return Py_FindMethod(interface_$interface->{NAME}\_methods, obj, name);");
	$self->deindent;
	$self->pidl("}");

	$self->pidl("");

	$self->pidl("PyTypeObject $interface->{NAME}_InterfaceType = {");
	$self->indent;
	$self->pidl("PyObject_HEAD_INIT(NULL) 0,");
	$self->pidl(".tp_name = \"$interface->{NAME}\",");
	$self->pidl(".tp_basicsize = sizeof($interface->{NAME}_InterfaceObject),");
	$self->pidl(".tp_dealloc = interface_$interface->{NAME}_dealloc,");
	$self->pidl(".tp_getattr = interface_$interface->{NAME}_getattr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->register_module_method($interface->{NAME}, "interface_$interface->{NAME}", "METH_VARARGS|METH_KEYWORDS", "NULL");
	$self->pidl("static PyObject *interface_$interface->{NAME}(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$interface->{NAME}_InterfaceObject *ret;");
	$self->pidl("const char *binding_string;");
	$self->pidl("struct cli_credentials *credentials;");
	$self->pidl("struct loadparm_context *lp_ctx;");
	$self->pidl("TALLOC_CTX *mem_ctx = NULL;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	# FIXME: Arguments: binding string, credentials, loadparm context
	$self->pidl("ret = PyObject_New($interface->{NAME}_InterfaceObject, &$interface->{NAME}_InterfaceType);");
	$self->pidl("");

	$self->pidl("status = dcerpc_pipe_connect(NULL, &ret->pipe, binding_string, ");
	$self->pidl("             &ndr_table_$interface->{NAME}, credentials, NULL, lp_ctx);");
	$self->handle_ntstatus("status", "NULL", "mem_ctx");

	$self->pidl("return (PyObject *)ret;");
	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("");

	$self->pidl_hdr("\n");
	$self->pidl_hdr("#endif /* _HEADER_NDR_$interface->{NAME} */\n");
}

sub register_module_method($$$$$)
{
	my ($self, $fn_name, $pyfn_name, $flags, $doc) = @_;

	push (@{$self->{module_methods}}, [$fn_name, $pyfn_name, $flags, $doc])
}

sub assign($$$)
{
	my ($self, $dest, $src) = @_;
	if ($dest =~ /^\&/) {
		$self->pidl("memcpy($dest, $src, sizeof(*$dest));");
	} else {
		$self->pidl("$dest = $src;");
	}
}

sub ConvertObjectFromPythonData($$$$$$)
{
	my ($self, $mem_ctx, $cvar, $ctype, $target, $fail) = @_;

	die("undef type for $cvar") unless(defined($ctype));

	if (ref($ctype) ne "HASH") {
		$ctype = getType($ctype);
	}

	if (ref($ctype) ne "HASH") {
		$self->pidl("$target = FIXME($cvar);");
		return;
	}

	my $actual_ctype = $ctype;
	if ($ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "ENUM" or $actual_ctype->{TYPE} eq "BITMAP" or 
		$actual_ctype->{TYPE} eq "SCALAR" and (
		expandAlias($actual_ctype->{NAME}) =~ /^(u?int[0-9]+|hyper|NTTIME|time_t|NTTIME_hyper|NTTIME_1sec|dlong|udlong|udlongr)$/)) {
		$self->pidl("PY_CHECK_TYPE(PyInt, $cvar, $fail);");
		$self->pidl("$target = PyInt_AsLong($cvar);");
		return;
	}

	if ($actual_ctype->{TYPE} eq "STRUCT") {
		$self->pidl("PY_CHECK_TYPE($ctype->{NAME}, $cvar, $fail);");
		$self->assign($target, "py_talloc_get_ptr($cvar)");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "DATA_BLOB") {
		$self->pidl("$target = data_blob_talloc($mem_ctx, PyString_AsString($cvar), PyString_Size($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and 
		($actual_ctype->{NAME} eq "string" or $actual_ctype->{NAME} eq "nbt_string" or $actual_ctype->{NAME} eq "nbt_name" or $actual_ctype->{NAME} eq "wrepl_nbt_name")) {
		$self->pidl("$target = talloc_strdup($mem_ctx, PyString_AsString($cvar));");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "ipv4address") {
		$self->pidl("$target = FIXME($cvar);");
		return;
		}


	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "NTSTATUS") {
		$self->pidl("$target = PyInt_AsLong($cvar);");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "WERROR") {
		$self->pidl("$target = PyInt_AsLong($cvar);");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "string_array") {
		$self->pidl("$target = FIXME($cvar);");
		return;
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "pointer") {
		$self->assign($target, "PyCObject_AsVoidPtr($cvar)");
		return;
	}

	die("unknown type ".mapTypeName($ctype) . ": $cvar");

}

sub ConvertObjectFromPythonLevel($$$$$$$$)
{
	my ($self, $env, $mem_ctx, $py_var, $e, $l, $var_name, $fail) = @_;

	if ($l->{TYPE} eq "POINTER") {
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($py_var == Py_None) {");
			$self->indent;
			$self->pidl("$var_name = NULL;");
			$self->deindent;
			$self->pidl("} else {");
			$self->indent;
		}
		$self->ConvertObjectFromPythonLevel($env, $mem_ctx, $py_var, $e, GetNextLevel($e, $l), get_value_of($var_name), $fail);
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY") {
		if (is_charset_array($e, $l)) {
			$self->pidl(get_pointer_to($var_name) . " = PyString_AsString(PyUnicode_AsEncodedString($py_var, \"utf-8\", \"ignore\"));");
		} else {
			my $counter = "$e->{NAME}_cntr_$l->{LEVEL_INDEX}";
			$self->pidl("{");
			$self->indent;
			$self->pidl("int $counter;");
			$self->pidl("$var_name = talloc_array_ptrtype($mem_ctx, $var_name, PyList_Size($py_var));");
			$self->pidl("for ($counter = 0; $counter < PyList_Size($py_var); $counter++) {");
			$self->indent;
			$self->ConvertObjectFromPythonLevel($env, $var_name, "PyList_GetItem($py_var, $counter)", $e, GetNextLevel($e, $l), $var_name."[$counter]", $fail);
			$self->deindent;
			$self->pidl("}");
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "DATA") {

		if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE}) or 
			Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
			$var_name = get_pointer_to($var_name);
		}
		$self->ConvertObjectFromPythonData($mem_ctx, $py_var, $l->{DATA_TYPE}, $var_name, $fail);
	} elsif ($l->{TYPE} eq "SWITCH") {
		$var_name = get_pointer_to($var_name);
		my $switch = ParseExpr($l->{SWITCH_IS}, $env, $e);
		$self->pidl("$var_name = py_export_" . GetNextLevel($e, $l)->{DATA_TYPE} . "($mem_ctx, $switch, $py_var);");
	} elsif ($l->{TYPE} eq "SUBCONTEXT") {
		$self->pidl("#error Subcontext not yet supported");
	} else {
		die("unknown level type $l->{TYPE}");
	}
}

sub ConvertObjectFromPython($$$$$$$)
{
	my ($self, $env, $mem_ctx, $ctype, $cvar, $target, $fail) = @_;

	$self->ConvertObjectFromPythonLevel($env, $mem_ctx, $cvar, $ctype, $ctype->{LEVELS}[0], $target, $fail);
}

sub ConvertScalarToPython($$$)
{
	my ($self, $ctypename, $cvar) = @_;

	die("expected string for $cvar, not $ctypename") if (ref($ctypename) eq "HASH");

	$ctypename = expandAlias($ctypename);

	if ($ctypename =~ /^(int|long|char|u?int[0-9]+|hyper|dlong|udlong|udlongr|time_t|NTTIME_hyper|NTTIME|NTTIME_1sec)$/) {
		return "PyInt_FromLong($cvar)";
	}

	if ($ctypename eq "DATA_BLOB") {
		return "PyString_FromStringAndSize($cvar->data, $cvar->length)";
	}

	if ($ctypename eq "NTSTATUS") {
		return "PyInt_FromLong(NT_STATUS_V($cvar))";
	}

	if ($ctypename eq "WERROR") {
		return "PyInt_FromLong(W_ERROR_V($cvar))";
	}

	if (($ctypename eq "string" or $ctypename eq "nbt_string" or $ctypename eq "nbt_name" or $ctypename eq "wrepl_nbt_name")) {
		return "PyString_FromString($cvar)";
	}

	# Not yet supported
	if ($ctypename eq "string_array") { return "PyCObject_FromVoidPtr($cvar)"; }
	if ($ctypename eq "ipv4address") { return "PyCObject_FromVoidPtr($cvar)"; }
	if ($ctypename eq "pointer") {
		return "PyCObject_FromVoidPtr($cvar, talloc_free)";
	}

	die("Unknown scalar type $ctypename");
}

sub ConvertObjectToPythonData($$$$)
{
	my ($self, $ctype, $cvar) = @_;

	die("undef type for $cvar") unless(defined($ctype));

	if (ref($ctype) ne "HASH") {
		if (not hasType($ctype)) {
			if (ref($ctype) eq "HASH") {
				return "py_import_$ctype->{TYPE}_$ctype->{NAME}($cvar)";
			} else {
				return "py_import_$ctype($cvar)"; # best bet
			}
		}

		$ctype = getType($ctype);
	}

	my $actual_ctype = $ctype;
	if ($ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "ENUM") {
		return $self->ConvertScalarToPython(Parse::Pidl::Typelist::enum_type_fn($actual_ctype), $cvar);
	}

	if ($actual_ctype->{TYPE} eq "BITMAP") {
		return $self->ConvertScalarToPython(Parse::Pidl::Typelist::bitmap_type_fn($actual_ctype), $cvar);
	}

	if ($actual_ctype->{TYPE} eq "SCALAR") {
		return $self->ConvertScalarToPython($actual_ctype->{NAME}, $cvar);
	}

	if ($actual_ctype->{TYPE} eq "STRUCT") {
		# FIXME: if $cvar is not a pointer, do a talloc_dup()
		return "py_talloc_import(&$ctype->{NAME}_Type, $cvar)";
	}

	die("unknown type ".mapTypeName($ctype) . ": $cvar");
}

sub ConvertObjectToPythonLevel($$$$)
{
	my ($self, $env, $e, $l, $var_name, $py_var) = @_;

	if ($l->{TYPE} eq "POINTER") {
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->pidl("if ($var_name == NULL) {");
			$self->indent;
			$self->pidl("$py_var = Py_None;");
			$self->deindent;
			$self->pidl("} else {");
			$self->indent;
		}
		$self->ConvertObjectToPythonLevel($env, $e, GetNextLevel($e, $l), get_value_of($var_name), $py_var);
		if ($l->{POINTER_TYPE} ne "ref") {
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "ARRAY") {
		if (is_charset_array($e, $l)) {
			$var_name = get_pointer_to($var_name);
			$self->pidl("$py_var = PyUnicode_Decode($var_name, strlen($var_name), \"utf-8\", \"ignore\");");
		} else {
			die("No SIZE_IS for array $var_name") unless (defined($l->{SIZE_IS}));
			my $length = $l->{SIZE_IS};
			if (defined($l->{LENGTH_IS})) {
				$length = $l->{LENGTH_IS};
			}

			$length = ParseExpr($length, $env, $e);
			$self->pidl("$py_var = PyList_New($length);");
			$self->pidl("{");
			$self->indent;
			my $counter = "$e->{NAME}_cntr_$l->{LEVEL_INDEX}";
			$self->pidl("int $counter;");
			$self->pidl("for ($counter = 0; $counter < $length; $counter++) {");
			$self->indent;
			my $member_var = "py_$e->{NAME}_$l->{LEVEL_INDEX}";
			$self->pidl("PyObject *$member_var;");
			$self->ConvertObjectToPythonLevel($env, $e, GetNextLevel($e, $l), $var_name."[$counter]", $member_var);
			$self->pidl("PyList_SetItem($py_var, $counter, $member_var);");
			$self->deindent;
			$self->pidl("}");
			$self->deindent;
			$self->pidl("}");
		}
	} elsif ($l->{TYPE} eq "SWITCH") {
		$var_name = get_pointer_to($var_name);
		my $switch = ParseExpr($l->{SWITCH_IS}, $env, $e);
		$self->pidl("$py_var = py_import_" . GetNextLevel($e, $l)->{DATA_TYPE} . "($switch, $var_name);");
	} elsif ($l->{TYPE} eq "DATA") {
		if (not Parse::Pidl::Typelist::is_scalar($l->{DATA_TYPE}) or 
			Parse::Pidl::Typelist::scalar_is_reference($l->{DATA_TYPE})) {
			$var_name = get_pointer_to($var_name);
		}
		my $conv = $self->ConvertObjectToPythonData($l->{DATA_TYPE}, $var_name);
		$self->pidl("$py_var = $conv;");
	} elsif ($l->{TYPE} eq "SUBCONTEXT") {
		$self->pidl("FIXME");
	} else {
		die("Unknown level type $l->{TYPE} $var_name");
	}
}

sub ConvertObjectToPython($$$$$)
{
	my ($self, $env, $ctype, $cvar, $py_var) = @_;

	$self->ConvertObjectToPythonLevel($env, $ctype, $ctype->{LEVELS}[0], $cvar, $py_var);
}

sub Parse($$$$$)
{
    my($self,$basename,$ndr,$ndr_hdr,$hdr) = @_;
    
    my $py_hdr = $hdr;
    $py_hdr =~ s/ndr_([^\/]+)$/py_$1/g;

    $self->pidl_hdr("/* header auto-generated by pidl */\n\n");
	
    $self->pidl("
/* Python wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include <Python.h>
#include \"librpc/rpc/dcerpc.h\"
#include \"scripting/python/pytalloc.h\"
#include \"$hdr\"
#include \"$ndr_hdr\"
#include \"$py_hdr\"

#define PY_CHECK_TYPE(type, var, fail) \\
	if (!type ## _Check(var)) {\\
		PyErr_Format(PyExc_TypeError, \"Expected type %s\", type ## _Type.tp_name); \\
		fail; \\
	}
");

	foreach my $x (@$ndr) {
	    ($x->{TYPE} eq "INTERFACE") && $self->Interface($x, $basename);
		($x->{TYPE} eq "IMPORT") && $self->Import(@{$x->{PATHS}});
	}
	
	$self->pidl("static PyMethodDef $basename\_methods[] = {");
	$self->indent;
	foreach (@{$self->{module_methods}}) {
		my ($fn_name, $pyfn_name, $flags, $doc) = @$_;
		$self->pidl("{ \"$fn_name\", (PyCFunction)$pyfn_name, $flags, $doc },");
	}
	
	$self->pidl("{ NULL, NULL, 0, NULL }");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->pidl("void init$basename(void)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("PyObject *m;");
	$self->pidl("m = Py_InitModule(\"$basename\", $basename\_methods);");
	foreach my $name (keys %{$self->{constants}}) {
		my $py_obj;
		my ($ctype, $cvar) = @{$self->{constants}->{$name}};
		if ($cvar =~ /^[0-9]+$/ or $cvar =~ /^0x[0-9a-fA-F]+$/) {
			$py_obj = "PyInt_FromLong($cvar)";
		} elsif ($cvar =~ /^".*"$/) {
			$py_obj = "PyString_FromString($cvar)";
		} else {
			$py_obj = $self->ConvertObjectToPythonData($ctype, $cvar);
		}

		$self->pidl("PyModule_AddObject(m, \"$name\", $py_obj);");
	}
	$self->deindent;
	$self->pidl("}");
    return ($self->{res_hdr}, $self->{res});
}

1;
