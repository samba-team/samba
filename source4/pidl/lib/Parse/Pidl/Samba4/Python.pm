###################################################
# Python function wrapper generator
# Copyright jelmer@samba.org 2007
# released under the GNU GPL

package Parse::Pidl::Samba4::Python;

use Exporter;
@ISA = qw(Exporter);

use strict;
use Parse::Pidl::Typelist;
use Parse::Pidl::Util qw(has_property ParseExpr);

use vars qw($VERSION);
$VERSION = '0.01';

sub new($) {
	my ($class) = @_;
	my $self = { res => "", res_hdr => "", tabs => "", constants => {}};
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
    $self->{constants}->{$const->{NAME}} = [$const->{DATA}->{TYPE}, $const->{VALUE}];
}

sub FromTypeToPythonFunction($$)
{
	my ($self, $type) = @_;

	#FIXME
}

sub FromPythonToTypeFunction($$)
{
	my ($self, $type) = @_;

	#FIXME
}

sub TypeConstructor($$)
{
	my ($self, $type) = @_;

	$self->pidl("staticforward PyTypeObject $type->{NAME}_ObjectType;");
	$self->pidl("typedef struct {");
	$self->indent;
	$self->pidl("PyObject_HEAD");
	$self->pidl("void *object;"); # FIXME: Use real type rather than void
	$self->deindent;
	$self->pidl("} $type->{NAME}_Object;");

	$self->pidl("");

	$self->pidl("static PyObject *py_$type->{NAME}_getattr(PyTypeObject *obj, char *name)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return Py_None;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static void py_$type->{NAME}_dealloc(PyObject* self)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$type->{NAME}_Object *obj = ($type->{NAME}_Object *)self;");
	$self->pidl("talloc_free(obj->object);");
	$self->pidl("PyObject_Del(self);");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyObject *py_$type->{NAME}_setattr(PyTypeObject *obj, char *name, PyObject *value)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("return Py_None;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static PyTypeObject $type->{NAME}_ObjectType = {");
	$self->indent;
	$self->pidl("PyObject_HEAD_INIT(NULL) 0,");
	$self->pidl(".tp_name = (char *)\"$type->{NAME}\",");
	$self->pidl(".tp_basicsize = sizeof($type->{NAME}_Object),");
	$self->pidl(".tp_dealloc = py_$type->{NAME}_dealloc,");
	$self->pidl(".tp_getattr = py_$type->{NAME}_getattr,");
	$self->pidl(".tp_setattr = py_$type->{NAME}_setattr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->pidl("static PyObject *py_$type->{NAME}(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$type->{NAME}\_Object *ret;");
	$self->pidl("ret = PyObject_New($type->{NAME}_Object, &$type->{NAME}_ObjectType);");
	$self->pidl("return (PyObject *) ret;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub PythonFunction($$$)
{
	my ($self, $fn, $iface) = @_;

	$self->pidl("static PyObject *py_$fn->{NAME}(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$iface\_InterfaceObject *iface = ($iface\_InterfaceObject *)self;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");
	# FIXME
	$self->handle_ntstatus("status", "NULL");
	$self->pidl("return Py_None;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub handle_ntstatus($$$)
{
	my ($self, $var, $retval) = @_;

	$self->pidl("if (NT_STATUS_IS_ERR($var)) {");
	$self->indent;
	$self->pidl("PyErr_SetString(PyExc_RuntimeError, nt_errstr($var));");
	$self->pidl("return $retval;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub Interface($$)
{
	my($self,$interface) = @_;

	$self->pidl_hdr("#ifndef _HEADER_PYTHON_$interface->{NAME}\n");
	$self->pidl_hdr("#define _HEADER_PYTHON_$interface->{NAME}\n\n");

	$self->pidl_hdr("\n");

	$self->Const($_) foreach (@{$interface->{CONSTS}});

	foreach (@{$interface->{TYPES}}) {
		$self->FromTypeToPythonFunction($_);	
		$self->FromPythonToTypeFunction($_);	
		$self->TypeConstructor($_);
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

		$self->pidl("{ (char *)\"$fn_name\", (PyCFunction)py_$d->{NAME}, METH_VARARGS|METH_KEYWORDS, NULL },");
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
	$self->pidl(".tp_name = (char *)\"$interface->{NAME}\",");
	$self->pidl(".tp_basicsize = sizeof($interface->{NAME}_InterfaceObject),");
	$self->pidl(".tp_dealloc = interface_$interface->{NAME}_dealloc,");
	$self->pidl(".tp_getattr = interface_$interface->{NAME}_getattr,");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->pidl("static PyObject *interface_$interface->{NAME}(PyObject *self, PyObject *args)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("$interface->{NAME}_InterfaceObject *ret;");
	$self->pidl("const char *binding_string;");
	$self->pidl("struct cli_credentials *credentials;");
	$self->pidl("struct loadparm_context *lp_ctx;");
	$self->pidl("NTSTATUS status;");
	$self->pidl("");

	# FIXME: Arguments: binding string, credentials, loadparm context
	$self->pidl("ret = PyObject_New($interface->{NAME}_InterfaceObject, &$interface->{NAME}_InterfaceType);");
	$self->pidl("");

	$self->pidl("status = dcerpc_pipe_connect(NULL, &ret->pipe, binding_string, ");
	$self->pidl("             &ndr_table_$interface->{NAME}, credentials, NULL, lp_ctx);");
	$self->handle_ntstatus("status", "NULL");

	$self->pidl("return (PyObject *)ret;");
	$self->deindent;
	$self->pidl("}");
	
	$self->pidl("");

	$self->pidl_hdr("\n");
	$self->pidl_hdr("#endif /* _HEADER_NDR_$interface->{NAME} */\n");
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
	    ($x->{TYPE} eq "INTERFACE") && $self->Interface($x);
		($x->{TYPE} eq "IMPORT") && $self->Import(@{$x->{PATHS}});
	}
	
	$self->pidl("static PyMethodDef $basename\_methods[] = {");
	$self->indent;
	foreach my $x (@$ndr) {
	    next if ($x->{TYPE} ne "INTERFACE");
		$self->pidl("{ (char *)\"$x->{NAME}\", (PyCFunction)interface_$x->{NAME}, METH_VARARGS|METH_KEYWORDS, NULL },");

		foreach my $d (@{$x->{TYPES}}) {
			next if has_property($d, "nopython");
			next if ($d->{TYPE} eq "ENUM" or $d->{TYPE} eq "BITMAP");

			my $fn_name = $d->{NAME};

			$fn_name =~ s/^$x->{NAME}_//;
			$fn_name =~ s/^$basename\_//;

			$self->pidl("{ (char *)\"$fn_name\", (PyCFunction)py_$d->{NAME}, METH_VARARGS|METH_KEYWORDS, NULL },");
		}
	}
	
	$self->pidl("{ NULL, NULL, 0, NULL }");
	$self->deindent;
	$self->pidl("};");

	$self->pidl("");

	$self->pidl("void init$basename(void)");
	$self->pidl("{");
	$self->indent;
	$self->pidl("PyObject *m;");
	$self->pidl("m = Py_InitModule((char *)\"$basename\", $basename\_methods);");
	foreach (keys %{$self->{constants}}) {
		# FIXME: Handle non-string constants
		$self->pidl("PyModule_AddObject(m, \"$_\", PyString_FromString(" . $self->{constants}->{$_}->[1] . "));");
	}
	$self->deindent;
	$self->pidl("}");
    return ($self->{res_hdr}, $self->{res});
}

1;
