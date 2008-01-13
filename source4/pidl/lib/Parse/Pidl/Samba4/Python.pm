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
use Parse::Pidl::CUtil qw(get_value_of get_pointer_to);

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

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		my $conv = $self->ConvertObjectToPython($e->{TYPE}, "$name->$e->{NAME}");
		if (defined($e->{CASE})) {
			$self->pidl("$e->{CASE}: return $conv;");
		} else {
			$self->pidl("default: return $conv;");
		}
	}

	$self->deindent;
	$self->pidl("}");

	$self->pidl("PyErr_SetString(PyExc_TypeError, \"unknown union level\");");
	$self->pidl("return NULL;");
}

sub FromPythonToUnionFunction($$$$)
{
	my ($self, $type, $switch, $mem_ctx, $name) = @_;

	$self->pidl("switch ($switch) {");
	$self->indent;

	foreach my $e (@{$type->{ELEMENTS}}) {
		my $conv = $self->ConvertObjectFromPython($e->{TYPE}, "$name");
		if (defined($e->{CASE})) {
			$self->pidl("$e->{CASE}: return $conv;");
		} else {
			$self->pidl("default: return $conv;");
		}
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("PyErr_SetString(PyExc_TypeError, \"invalid union level value\");");
	$self->pidl("return NULL;");
}

sub PythonStruct($$$$)
{
	my ($self, $name, $cname, $d) = @_;

	$self->pidl("staticforward PyTypeObject $name\_ObjectType;");

	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_getattr(PyTypeObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("py_talloc_Object *py_object = (py_talloc_Object *)obj;");
	$self->pidl("$cname *object = py_talloc_get_type(py_object, $cname);");
	foreach my $e (@{$d->{ELEMENTS}}) {
		$self->pidl("if (!strcmp(name, \"$e->{NAME}\")) {");
		my $varname = "object->$e->{NAME}";
		$self->indent;
		$self->pidl("return ".$self->ConvertObjectToPython($e->{TYPE}, $varname) . ";");
		$self->deindent;
		$self->pidl("}");
	}
	$self->pidl("PyErr_SetString(PyExc_AttributeError, \"no such attribute\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_setattr(PyTypeObject *obj, char *name, PyObject *value)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("py_talloc_Object *py_object = (py_talloc_Object *)obj;");
	$self->pidl("$cname *object = py_talloc_get_type(py_object, $cname);");
	foreach my $e (@{$d->{ELEMENTS}}) {
		$self->pidl("if (!strcmp(name, \"$e->{NAME}\")) {");
		my $varname = "object->$e->{NAME}";
		$self->indent;
		$self->pidl("/* FIXME: talloc_free($varname) if necessary */");
		$self->pidl("$varname = " . $self->ConvertObjectFromPython($e->{TYPE}, "value") . ";");
		$self->deindent;
		$self->pidl("}");
	}
	$self->pidl("PyErr_SetString(PyExc_AttributeError, \"no such attribute\");");
	$self->pidl("return NULL;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyTypeObject $name\_ObjectType = {");
	$self->indent;
	$self->pidl("PyObject_HEAD_INIT(NULL) 0,");
	$self->pidl(".tp_name = \"$name\",");
	$self->pidl(".tp_basicsize = sizeof(py_talloc_Object),");
	$self->pidl(".tp_dealloc = (destructor)py_talloc_dealloc,");
	$self->pidl(".tp_getattr = (getattrfunc)py_$name\_getattr,");
	$self->pidl(".tp_setattr = (setattrfunc)py_$name\_setattr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	my $py_fnname = "py_$name";
	$self->pidl("static PyObject *$py_fnname(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$cname *ret = talloc_zero(NULL, $cname);");
	$self->pidl("return py_talloc_import(&$name\_ObjectType, ret);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	return $py_fnname;
}

sub PythonFunction($$$)
{
	my ($self, $fn, $iface) = @_;

	$self->pidl("static PyObject *py_$fn->{NAME}(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$iface\_InterfaceObject *iface = ($iface\_InterfaceObject *)self;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("TALLOC_CTX *mem_ctx = talloc_new(NULL);");
	$self->pidl("struct $fn->{NAME} r;");
	$self->pidl("PyObject *result;");
	my $result_size = 0;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->pidl("PyObject *py_$e->{NAME};");
		}
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$result_size++;
		}
	}
	if ($result_size > 0) {
		$self->pidl("");
		$self->pidl("ZERO_STRUCT(r.out);");
	}
	if ($fn->{RETURN_TYPE}) {
		$result_size++;
	}

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/in/,@{$e->{DIRECTION}})) {
			$self->pidl("r.in.$e->{NAME} = " . $self->ConvertObjectFromPython($e->{TYPE}, "py_$e->{NAME}") . ";");
		}
	}
	$self->pidl("status = dcerpc_$fn->{NAME}(iface->pipe, mem_ctx, &r);");
	$self->handle_ntstatus("status", "NULL", "mem_ctx");

	$self->pidl("result = PyTuple_New($result_size);");

	my $i = 0;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep(/out/,@{$e->{DIRECTION}})) {
			$self->pidl("PyTuple_SetItem(result, $i, " . $self->ConvertObjectToPython($e->{TYPE}, "r.out.$e->{NAME}") . ");");

			$i++;
		}
	}

	if (defined($fn->{RETURN_TYPE})) {
		$self->pidl("PyTuple_SetItem(result, $i, " . $self->ConvertObjectToPython($fn->{RETURN_TYPE}, "r.out.result") . ");");
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

		$self->register_module_method($fn_name, $py_fnname, "METH_VARARGS|METH_KEYWORDS", "NULL");
	}

	if ($d->{TYPE} eq "ENUM" or $d->{TYPE} eq "BITMAP") {
		$self->EnumAndBitmapConsts($d->{NAME}, $d);
	}

	if ($d->{TYPE} eq "TYPEDEF" and ($d->{DATA}->{TYPE} eq "ENUM" or $d->{DATA}->{TYPE} eq "BITMAP")) {
		$self->EnumAndBitmapConsts($d->{NAME}, $d->{DATA});
	}

	if ($actual_ctype->{TYPE} eq "UNION") {
		$self->pidl("PyObject *py_import_$d->{NAME}(" .mapTypeName($d) . " *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromUnionToPythonFunction($actual_ctype, "level", "in") if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl(mapTypeName($d) . " *py_export_$d->{NAME}(TALLOC_CTX *mem_ctx, PyObject *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromPythonToUnionFunction($actual_ctype, "level", "mem_ctx", "in") if ($actual_ctype->{TYPE} eq "UNION");
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

	$self->pidl("staticforward PyTypeObject $interface->{NAME}_InterfaceType;");
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

	$self->pidl("static PyObject *interface_$interface->{NAME}_getattr(PyTypeObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return Py_FindMethod(interface_$interface->{NAME}\_methods, (PyObject *)obj, name);");
	$self->deindent;
	$self->pidl("}");

	$self->pidl("");

	$self->pidl("static PyTypeObject $interface->{NAME}_InterfaceType = {");
	$self->indent;
	$self->pidl("PyObject_HEAD_INIT(NULL) 0,");
	$self->pidl(".tp_name = \"$interface->{NAME}\",");
	$self->pidl(".tp_basicsize = sizeof($interface->{NAME}_InterfaceObject),");
	$self->pidl(".tp_dealloc = (destructor)interface_$interface->{NAME}_dealloc,");
	$self->pidl(".tp_getattr = (getattrfunc)interface_$interface->{NAME}_getattr,");
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

sub ConvertObjectFromPython($$$)
{
	my ($self, $ctype, $cvar) = @_;

	die("undef type for $cvar") unless(defined($ctype));

	if (ref($ctype) ne "HASH") {
		$ctype = getType($ctype);
	}

	if (ref($ctype) ne "HASH") {
		return "FIXME($cvar)";
	}

	my $actual_ctype = $ctype;
	if ($ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "ENUM" or $actual_ctype->{TYPE} eq "BITMAP" or 
		$actual_ctype->{TYPE} eq "SCALAR" and (
		expandAlias($actual_ctype->{NAME}) =~ /^(uint[0-9]+|hyper|NTTIME|time_t|NTTIME_hyper|NTTIME_1sec|dlong|udlong)$/)) {
		return "PyInt_AsLong($cvar)";
	}

	if ($actual_ctype->{TYPE} eq "STRUCT") {
		return "py_talloc_get_type($cvar, " . mapTypeName($ctype) . ")";
	}

	if ($actual_ctype->{TYPE} eq "UNION") {
		return "py_export_$ctype->{NAME}($cvar)";
	}

	return "FIXME($cvar)";
}

sub ConvertObjectToPython($$$)
{
	my ($self, $ctype, $cvar) = @_;

	if ($cvar =~ /^[0-9]+$/ or $cvar =~ /^0x[0-9a-fA-F]+$/) {
		return "PyInt_FromLong($cvar)";
	}

	die("undef type for $cvar") unless(defined($ctype));

	if ($cvar =~ /^".*"$/) {
		return "PyString_FromString($cvar)";
	}

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

	if ($actual_ctype->{TYPE} eq "ENUM" or $actual_ctype->{TYPE} eq "BITMAP" or 
		($actual_ctype->{TYPE} eq "SCALAR" and 
		expandAlias($actual_ctype->{NAME}) =~ /^(int|long|char|u?int[0-9]+|hyper|dlong|udlong|udlongr|time_t|NTTIME_hyper|NTTIME|NTTIME_1sec)$/)) {
		return "PyInt_FromLong($cvar)";
	}

	if ($ctype->{TYPE} eq "TYPEDEF" and $actual_ctype->{TYPE} eq "UNION") {
		return "py_import_$ctype->{NAME}($cvar)";
	}

	if ($ctype->{TYPE} eq "TYPEDEF" and $actual_ctype->{TYPE} eq "STRUCT") {
		# FIXME: if $cvar is not a pointer, do a talloc_dup()
		return "py_talloc_import(&$ctype->{NAME}_ObjectType, $cvar)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and 
		expandAlias($actual_ctype->{NAME}) eq "DATA_BLOB") {
		return "PyString_FromStringAndSize($cvar->data, $cvar->length)";
	}

	if ($ctype->{TYPE} eq "STRUCT" or $ctype->{TYPE} eq "UNION") {
		return "py_import_$ctype->{TYPE}_$ctype->{NAME}($cvar)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "NTSTATUS") {
		return "PyInt_FromLong($cvar->v)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "WERROR") {
		return "PyInt_FromLong($cvar->v)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and 
		($actual_ctype->{NAME} eq "string" or $actual_ctype->{NAME} eq "nbt_string" or $actual_ctype->{NAME} eq "nbt_name" or $actual_ctype->{NAME} eq "wrepl_nbt_name")) {
		return "PyString_FromString($cvar)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "string_array") {
		return "FIXME($cvar)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "ipv4address") {
		return "FIXME($cvar)";
		}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "pointer") {
		return "PyCObject_FromVoidPtr($cvar, talloc_free)";
	}


	die("unknown type ".mapTypeName($ctype) . ": $cvar");
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
	foreach (keys %{$self->{constants}}) {
		# FIXME: Handle non-string constants
		$self->pidl("PyModule_AddObject(m, \"$_\", " .  $self->ConvertObjectToPython($self->{constants}->{$_}->[0], $self->{constants}->{$_}->[1]) . ");");
	}
	$self->deindent;
	$self->pidl("}");
    return ($self->{res_hdr}, $self->{res});
}

1;
