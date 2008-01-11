###################################################
# Python function wrapper generator
# Copyright jelmer@samba.org 2007-2008
# released under the GNU GPL

package Parse::Pidl::Samba4::Python;

use Exporter;
@ISA = qw(Exporter);

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapTypeName);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::CUtil qw(get_value_of get_pointer_of);

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
	$self->register_constant($const->{NAME}, $const->{DATA}->{TYPE}, $const->{VALUE});
}

sub register_constant($$$$)
{
	my ($self, $name, $type, $value) = @_;

	$self->{constants}->{$name} = [$type, $value];
}

sub EnumAndBitmapConsts($$$)
{
	my ($self, $name, $d) = @_;

	foreach my $e (@{$d->{ELEMENTS}}) {
		$e =~ /^([A-Za-z0-9_]+)=(.*)$/;
		my $cname = $1;
		
		$self->register_constant($cname, $d, $cname);
	}
}

sub FromUnionToPythonFunction($$)
{
	my ($self, $type) = @_;

	#FIXME

	$self->pidl("return NULL;");
}

sub FromStructToPythonFunction($$)
{
	my ($self, $type) = @_;

	#FIXME
	$self->pidl("return NULL;");
}

sub FromPythonToUnionFunction($$)
{
	my ($self, $type) = @_;

	#FIXME
	$self->pidl("return NULL;");
}

sub FromPythonToStructFunction($$)
{
	my ($self, $type) = @_;

	#FIXME
	$self->pidl("return NULL;");
}

sub PythonStruct($$$$)
{
	my ($self, $name, $cname, $d) = @_;

	$self->pidl("staticforward PyTypeObject $name\_ObjectType;");
	$self->pidl("typedef struct {");
	$self->indent;
	$self->pidl("PyObject_HEAD");
	$self->pidl("$cname *object;");
	$self->deindent;
	$self->pidl("} $name\_Object;");

	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_getattr(PyTypeObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$name\_Object *py_object = ($name\_Object *)obj;");
	$self->pidl("$cname *object = talloc_get_type(py_object->object, $cname);");
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

	$self->pidl("static void py_$name\_dealloc(PyObject* self)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$name\_Object *obj = ($name\_Object *)self;");
	$self->pidl("talloc_free(obj->object);");
	$self->pidl("PyObject_Del(self);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$name\_setattr(PyTypeObject *obj, char *name, PyObject *value)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$name\_Object *py_object = ($name\_Object *)obj;");
	$self->pidl("$cname *object = talloc_get_type(py_object->object, $cname);");
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
	$self->pidl(".tp_basicsize = sizeof($name\_Object),");
	$self->pidl(".tp_dealloc = (destructor)py_$name\_dealloc,");
	$self->pidl(".tp_getattr = (getattrfunc)py_$name\_getattr,");
	$self->pidl(".tp_setattr = (setattrfunc)py_$name\_setattr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	my $py_fnname = "py_$name";
	$self->pidl("static PyObject *$py_fnname(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$name\_Object *ret;");
	$self->pidl("ret = PyObject_New($name\_Object, &$name\_ObjectType);");
	$self->pidl("return (PyObject *) ret;");
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
	$self->pidl("struct dcerpc_$fn->{NAME} r;");
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
	if ($fn->{RETURN_TYPE}) {
		$result_size++;
	}
	$self->pidl("");
	$self->pidl("ZERO_STRUCT(r.out);");

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

	if ($fn->{RETURN_TYPE}) {
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

	if ($d->{TYPE} eq "STRUCT" or $d->{TYPE} eq "TYPEDEF" and 
		$d->{DATA}->{TYPE} eq "STRUCT") {
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

	if ($actual_ctype->{TYPE} eq "UNION" or $actual_ctype->{TYPE} eq "STRUCT") {
		$self->pidl("PyObject *py_import_$d->{NAME}(" .mapTypeName($d) . " *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromStructToPythonFunction($d) if ($actual_ctype->{TYPE} eq "STRUCT");
		$self->FromUnionToPythonFunction($d) if ($actual_ctype->{TYPE} eq "UNION");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");

		$self->pidl(mapTypeName($d) . " *py_export_$d->{NAME}(TALLOC_CTX *mem_ctx, PyObject *in)");
		$self->pidl("{");
		$self->indent;
		$self->FromPythonToStructFunction($d) if ($actual_ctype->{TYPE} eq "STRUCT");
		$self->FromPythonToUnionFunction($d) if ($actual_ctype->{TYPE} eq "UNION");
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

sub ConvertObjectFromPython($$$)
{
	my ($self, $ctype, $cvar) = @_;

	if (ref($ctype) ne "HASH") {
		$ctype = getType($ctype);
	}

	my $actual_ctype = $ctype;
	if ($ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $ctype->{DATA};
	}

	if ($actual_ctype->{TYPE} eq "ENUM" or $actual_ctype->{TYPE} eq "BITMAP" or 
		$actual_ctype->{TYPE} eq "SCALAR" and (
		$actual_ctype->{NAME} =~ /^(uint[0-9]+|hyper)$/)) {
		return "PyInt_AsLong($cvar)";
	}

	return "FIXME($cvar)";
}

sub ConvertObjectToPython($$$)
{
	my ($self, $ctype, $cvar) = @_;

	if ($cvar =~ /^".*"$/) {
		return "PyString_FromString($cvar)";
	}

	if (ref($ctype) ne "HASH") {
		$ctype = getType($ctype);
	}

	my $actual_ctype = $ctype;
	if ($ctype->{TYPE} eq "TYPEDEF") {
		$actual_ctype = $ctype->{DATA};
	}

	if ($cvar =~ /^[0-9]+$/ or 
		$actual_ctype->{TYPE} eq "ENUM" or $actual_ctype->{TYPE} eq "BITMAP" or 
		$actual_ctype->{TYPE} eq "SCALAR" and (
		$actual_ctype->{NAME} =~ /^(uint[0-9]+|hyper)$/)) {
		return "PyInt_FromLong($cvar)";
	}

	if ($ctype->{TYPE} eq "TYPEDEF" and (
			$actual_ctype->{TYPE} eq "STRUCT" or 
			$actual_ctype->{TYPE} eq "UNION")) {
		return "py_import_$ctype->{NAME}($cvar)";
	}

	if ($ctype->{TYPE} eq "STRUCT" or $ctype->{TYPE} eq "UNION") {
		return "py_import_$ctype->{TYPE}_$ctype->{NAME}($cvar)";
	}

	if ($actual_ctype->{TYPE} eq "SCALAR" and $actual_ctype->{NAME} eq "NTSTATUS") {
		return "PyInt_FromLong($cvar->v)";
	}

	die("unknown type ".mapTypeName($ctype) . ": $cvar");
}

sub Parse($$$$)
{
    my($self,$basename,$ndr,$hdr) = @_;
    
    my $py_hdr = $hdr;
    $py_hdr =~ s/ndr_([^\/]+)$/py_$1/g;

    $self->pidl_hdr("/* header auto-generated by pidl */\n\n");
	
    $self->pidl("
/* Python wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include <Python.h>
#include \"librpc/rpc/dcerpc.h\"
#include \"$hdr\"
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
