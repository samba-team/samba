###################################################
# EJS function wrapper generator
# Copyright jelmer@samba.org 2005
# Copyright Andrew Tridgell 2005
# released under the GNU GPL

package EjsClient;

use strict;
use pidl::typelist;

my($res);

sub pidl ($)
{
	$res .= shift;
}

# this should probably be in ndr.pm
sub GenerateStructEnv($)
{
	my $x = shift;
	my %env;

	foreach my $e (@{$x->{ELEMENTS}}) {
		$env{$e->{NAME}} = "r->$e->{NAME}";
	}

	$env{"this"} = "r";

	return \%env;
}

sub GenerateFunctionInEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

sub GenerateFunctionOutEnv($)
{
	my $fn = shift;
	my %env;

	foreach my $e (@{$fn->{ELEMENTS}}) {
		if (grep (/out/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->out.$e->{NAME}";
		} elsif (grep (/in/, @{$e->{DIRECTION}})) {
			$env{$e->{NAME}} = "r->in.$e->{NAME}";
		}
	}

	return \%env;
}

sub get_pointer_to($)
{
	my $var_name = shift;
	
	if ($var_name =~ /^\*(.*)$/) {
		return $1;
	} elsif ($var_name =~ /^\&(.*)$/) {
		return "&($var_name)";
	} else {
		return "&$var_name";
	}
}

sub get_value_of($)
{
	my $var_name = shift;

	if ($var_name =~ /^\&(.*)$/) {
		return $1;
	} else {
		return "*$var_name";
	}
}


###########################
# pull a scalar element
sub EjsPullScalar($$)
{
	my $e = shift;
	my $env = shift;
	my $var = util::ParseExpr($e->{NAME}, $env);
	my $ptr = get_pointer_to($var);
	pidl "\tNDR_CHECK(ejs_pull_$e->{TYPE}(ejs, v, \"$e->{NAME}\", $ptr));\n";
}

###########################
# pull a string element
sub EjsPullString($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $var = util::ParseExpr($e->{NAME}, $env);
	my $ptr = get_pointer_to($var);
	pidl "\tNDR_CHECK(ejs_pull_string(ejs, v, \"$e->{NAME}\", $ptr));\n";
}


###########################
# pull an arrar element
# only handles a very limited range of array types so far
sub EjsPullArray($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $length = util::ParseExpr($l->{LENGTH_IS}, $env);
	my $var = util::ParseExpr($e->{NAME}, $env);
	my $ptr = get_pointer_to($var);
	pidl "\tNDR_CHECK(ejs_pull_array(ejs, v, \"$e->{NAME}\", $length, sizeof($var\[0]), (void **)$ptr, (ejs_pull_t)ejs_pull_$e->{TYPE}));\n";
}

###########################
# pull a structure element
sub EjsPullElement($$)
{
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	if (util::has_property($e, "charset")) {
		EjsPullString($e, $l, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPullArray($e, $l, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPullScalar($e, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled pull type $l->{TYPE}\");\n";
	}
}

###########################
# pull a struct
sub EjsStructPull($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	pidl "\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, struct $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_pull_struct_start(ejs, &v, name));\n";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPullElement($e, $env);
	}
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}

###########################
# pull a union
sub EjsUnionPull($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	pidl "\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, union $name *r)\n{\n";
	pidl "return ejs_panic(ejs, \"union pull not handled\");\n";
	pidl "}\n\n";
}

###########################
# pull a enum
sub EjsEnumPull($$)
{
	my $name = shift;
	my $d = shift;
	pidl "\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, enum $name *r)\n{\n";
	pidl "\tunsigned e;\n";
	pidl "\tNDR_CHECK(ejs_pull_enum(ejs, v, name, &e));\n";
	pidl "\t*r = e;\n";
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}


###########################
# generate a structure pull
sub EjsTypedefPull($)
{
	my $d = shift;
	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPull($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled pull typedef $d->{NAME} of type $d->{TYPE}\n";
	}
}

#####################
# generate a function
sub EjsPullFunction($)
{
	my $d = shift;
	my $env = GenerateFunctionInEnv($d);
	my $name = $d->{NAME};

	pidl "\nstatic NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, struct $name *r)\n";
	pidl "{\n";

	pidl "\tNDR_CHECK(ejs_pull_struct_start(ejs, &v, \"input\"));\n";

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/in/, @{$e->{DIRECTION}}));
		EjsPullElement($e, $env);
	}

	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}


###########################
# pull a scalar element
sub EjsPushScalar($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $var = util::ParseExpr($e->{NAME}, $env);

	$var = get_pointer_to($var);

	pidl "\tNDR_CHECK(ejs_push_$e->{TYPE}(ejs, v, \"$e->{NAME}\", $var));\n";
}

###########################
# pull a string element
sub EjsPushString($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $var = util::ParseExpr($e->{NAME}, $env);

	pidl "\tNDR_CHECK(ejs_push_string(ejs, v, \"$e->{NAME}\", $var));\n";
}

###########################
# pull a pointer element
sub EjsPushPointer($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $var = util::ParseExpr($e->{NAME}, $env);

	while ($l->{TYPE} eq "POINTER") {
		$var = get_value_of($var);
		$l = Ndr::GetNextLevel($e, $l);
	}
	$var = get_pointer_to($var);		

	pidl "\tNDR_CHECK(ejs_push_$e->{TYPE}(ejs, v, \"$e->{NAME}\", $var));\n";
}


###########################
# push an arrar element
# only handles a very limited range of array types so far
sub EjsPushArray($$$)
{
	my $e = shift;
	my $l = shift;
	my $env = shift;
	my $length = util::ParseExpr($l->{LENGTH_IS}, $env);
	my $var = util::ParseExpr($e->{NAME}, $env);
	pidl "\tNDR_CHECK(ejs_push_array(ejs, v, \"$e->{NAME}\", $length, sizeof($var\[0]), (void *)$var, (ejs_push_t)ejs_push_$e->{TYPE}));\n";
}

###########################
# push a structure element
sub EjsPushElement($$)
{
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	if (util::has_property($e, "charset")) {
		EjsPushString($e, $l, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPushArray($e, $l, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPushScalar($e, $l, $env);
	} elsif (($l->{TYPE} eq "POINTER")) {
		EjsPushPointer($e, $l, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled push type $l->{TYPE}\");\n";
	}
}

###########################
# push a struct
sub EjsStructPush($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	pidl "\nstatic NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const struct $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_push_struct_start(ejs, &v, name));\n";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPushElement($e, $env);
	}
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}

###########################
# push a union
sub EjsUnionPush($$)
{
	my $name = shift;
	my $d = shift;
	pidl "\nstatic NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const union $name *r)\n{\n";
	pidl "return ejs_panic(ejs, \"union push not handled\");\n";
	pidl "}\n\n";
}

###########################
# push a enum
sub EjsEnumPush($$)
{
	my $name = shift;
	my $d = shift;
	pidl "\nstatic NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const enum $name *r)\n{\n";
	pidl "\tunsigned e = *r;\n";
	pidl "\tNDR_CHECK(ejs_push_enum(ejs, v, name, &e));\n";
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}


###########################
# generate a structure push
sub EjsTypedefPush($)
{
	my $d = shift;
	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPush($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled push typedef $d->{NAME} of type $d->{TYPE}\n";
	}
}


#####################
# generate a function
sub EjsPushFunction($)
{
	my $d = shift;
	my $env = GenerateFunctionOutEnv($d);

	pidl "\nstatic NTSTATUS ejs_push_$d->{NAME}(struct ejs_rpc *ejs, struct MprVar *v, const struct $d->{NAME} *r)\n";
	pidl "{\n";

	pidl "\tNDR_CHECK(ejs_push_struct_start(ejs, &v, \"output\"));\n";

	foreach my $e (@{$d->{ELEMENTS}}) {
		next unless (grep(/out/, @{$e->{DIRECTION}}));
		EjsPushElement($e, $env);
	}

	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}


#################################
# generate a ejs mapping function
sub EjsFunction($)
{
	my $d = shift;
	my $name = $d->{NAME};

	pidl "static int ejs_$name(int eid, int argc, struct MprVar **argv)\n";
	pidl "{\n";
	pidl "\treturn ejs_rpc_call(eid, argc, argv, \"$name\", (ejs_pull_function_t)ejs_pull_$name, (ejs_push_function_t)ejs_push_$name);\n";
	pidl "}\n\n";
}

#####################################################################
# parse the interface definitions
sub EjsInterface($)
{
	my($interface) = shift;
	my @fns = ();
	my $name = $interface->{NAME};

	foreach my $d (@{$interface->{TYPEDEFS}}) {
		EjsTypedefPush($d);
		EjsTypedefPull($d);
	}

	foreach my $d (@{$interface->{FUNCTIONS}}) {
		next if not defined($d->{OPNUM});
		
		EjsPullFunction($d);
		EjsPushFunction($d);
		EjsFunction($d);

		push (@fns, $d->{NAME});
	}

	pidl "void setup_ejs_$name(void)\n";
	pidl "{\n";
	foreach (@fns) {
		pidl "\tejsDefineCFunction(-1, \"dcerpc_$_\", ejs_$_, NULL, MPR_VAR_SCRIPT_HANDLE);\n";
	}
	pidl "}\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($$)
{
    my($ndr,$hdr) = @_;

    $res = "";
    pidl "
/* EJS wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include \"lib/ejs/ejs.h\"
#include \"$hdr\"
#include \"scripting/ejs/ejsrpc.h\"

";
    foreach my $x (@{$ndr}) {
	    if ($x->{TYPE} eq "INTERFACE") {
		    ($x->{TYPE} eq "INTERFACE") && EjsInterface($x);
	    }
    }

    return $res;
}

1;
