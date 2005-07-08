###################################################
# EJS function wrapper generator
# Copyright jelmer@samba.org 2005
# Copyright Andrew Tridgell 2005
# released under the GNU GPL

package EjsClient;

use strict;
use pidl::typelist;

my($res);
my %constants;

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
		if ($e->{NAME}) {
			$env{$e->{NAME}} = "r->$e->{NAME}";
		}
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

#####################################################################
# work out is a parse function should be declared static or not
sub fn_prefix($)
{
	my $fn = shift;

	return "" if (util::has_property($fn, "public"));
	return "static ";
}

###########################
# pull a scalar element
sub EjsPullScalar($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;

	return if (util::has_property($e, "value"));

	$var = get_pointer_to($var);
	# have to handle strings specially :(
	if ($e->{TYPE} eq "string") {
		$var = get_pointer_to($var);
	}
	pidl "\tNDR_CHECK(ejs_pull_$e->{TYPE}(ejs, v, $name, $var));\n";
}

###########################
# pull a pointer element
sub EjsPullPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "\tif (ejs_pull_null(ejs, v, $name)) {\n";
	pidl "\t$var = NULL;\n";
	pidl "\t} else {\n";
	pidl "\tEJS_ALLOC(ejs, $var);\n";
	$var = get_value_of($var);		
	EjsPullElement($e, Ndr::GetNextLevel($e, $l), $var, $name, $env);
	pidl "}\n";
}

###########################
# pull a string element
sub EjsPullString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	$var = get_pointer_to($var);
	pidl "\tNDR_CHECK(ejs_pull_string(ejs, v, $name, $var));\n";
}


###########################
# pull an arrar element
sub EjsPullArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $length = util::ParseExpr($l->{LENGTH_IS}, $env);
	my $pl = Ndr::GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	my $avar = $var . "[i]";
	pidl "\t{ uint32_t i;\n";
	if (!$l->{IS_FIXED}) {
		pidl "\tEJS_ALLOC_N(ejs, $var, $length);\n";
	}
	pidl "\tfor (i=0;i<$length;i++) {\n";
	pidl "\tchar *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);\n";
	EjsPullElement($e, Ndr::GetNextLevel($e, $l), $avar, "id", $env);
	pidl "\ttalloc_free(id);\n";
	pidl "\t}\nejs_push_uint32(ejs, v, $name \".length\", &i); }\n";
}

###########################
# pull a switch element
sub EjsPullSwitch($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $switch_var = util::ParseExpr($l->{SWITCH_IS}, $env);
	pidl "ejs_set_switch(ejs, $switch_var);\n";
	EjsPullElement($e, Ndr::GetNextLevel($e, $l), $var, $name, $env);
}

###########################
# pull a structure element
sub EjsPullElement($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	if (util::has_property($e, "charset")) {
		EjsPullString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPullArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPullScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "POINTER")) {
		EjsPullPointer($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		EjsPullSwitch($e, $l, $var, $name, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled pull type $l->{TYPE}\");\n";
	}
}

#############################################
# pull a structure/union element at top level
sub EjsPullElementTop($$)
{
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	my $var = util::ParseExpr($e->{NAME}, $env);
	my $name = "\"$e->{NAME}\"";
	EjsPullElement($e, $l, $var, $name, $env);
}

###########################
# pull a struct
sub EjsStructPull($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, struct $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_pull_struct_start(ejs, &v, name));\n";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPullElementTop($e, $env);
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
	my $have_default = 0;
	my $env = GenerateStructEnv($d);
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, union $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_pull_struct_start(ejs, &v, name));\n";
	pidl "switch (ejs->switch_var) {\n";
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$e->{CASE}:";
		if ($e->{TYPE} ne "EMPTY") {
			EjsPullElementTop($e, $env);
		}
		pidl "break;\n";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ejs_panic(ejs, \"Bad switch value\");";
	}
	pidl "}\nreturn NT_STATUS_OK;\n}\n";
}

###########################
# pull a enum
sub EjsEnumPull($$)
{
	my $name = shift;
	my $d = shift;
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, enum $name *r)\n{\n";
	pidl "\tunsigned e;\n";
	pidl "\tNDR_CHECK(ejs_pull_enum(ejs, v, name, &e));\n";
	pidl "\t*r = e;\n";
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}

###########################
# pull a bitmap
sub EjsBitmapPull($$)
{
	my $name = shift;
	my $d = shift;
	my $type_fn = $d->{BASE_TYPE};
	my($type_decl) = typelist::mapType($d->{BASE_TYPE});
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_pull_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, $type_decl *r)\n{\n";
	pidl "return ejs_pull_$type_fn(ejs, v, name, r);\n";
	pidl "}\n";
}


###########################
# generate a structure pull
sub EjsTypedefPull($)
{
	my $d = shift;
	return if (util::has_property($d, "noejs"));
	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPull($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'BITMAP') {
		EjsBitmapPull($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled pull typedef $d->{NAME} of type $d->{DATA}->{TYPE}\n";
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
		EjsPullElementTop($e, $env);
	}

	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}


###########################
# push a scalar element
sub EjsPushScalar($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	$var = get_pointer_to($var);
	pidl "\tNDR_CHECK(ejs_push_$e->{TYPE}(ejs, v, $name, $var));\n";
}

###########################
# push a string element
sub EjsPushString($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "\tNDR_CHECK(ejs_push_string(ejs, v, $name, $var));\n";
}

###########################
# push a pointer element
sub EjsPushPointer($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	pidl "\tif (NULL == $var) {\n";
	pidl "\tNDR_CHECK(ejs_push_null(ejs, v, $name));\n";
	pidl "\t} else {\n";
	$var = get_value_of($var);		
	EjsPushElement($e, Ndr::GetNextLevel($e, $l), $var, $name, $env);
	pidl "}\n";
}

###########################
# push a switch element
sub EjsPushSwitch($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $switch_var = util::ParseExpr($l->{SWITCH_IS}, $env);
	pidl "ejs_set_switch(ejs, $switch_var);\n";
	EjsPushElement($e, Ndr::GetNextLevel($e, $l), $var, $name, $env);
}


###########################
# push an arrar element
sub EjsPushArray($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	my $length = util::ParseExpr($l->{LENGTH_IS}, $env);
	my $pl = Ndr::GetPrevLevel($e, $l);
	if ($pl && $pl->{TYPE} eq "POINTER") {
		$var = get_pointer_to($var);
	}
	my $avar = $var . "[i]";
	pidl "{ uint32_t i; for (i=0;i<$length;i++) {\n";
	pidl "\tconst char *id = talloc_asprintf(ejs, \"%s.%u\", $name, i);\n";
	EjsPushElement($e, Ndr::GetNextLevel($e, $l), $avar, "id", $env);
	pidl "}\nejs_push_uint32(ejs, v, $name \".length\", &i); }\n";
}

################################
# push a structure/union element
sub EjsPushElement($$$$$)
{
	my ($e, $l, $var, $name, $env) = @_;
	if (util::has_property($e, "charset")) {
		EjsPushString($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "ARRAY") {
		EjsPushArray($e, $l, $var, $name, $env);
	} elsif ($l->{TYPE} eq "DATA") {
		EjsPushScalar($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "POINTER")) {
		EjsPushPointer($e, $l, $var, $name, $env);
	} elsif (($l->{TYPE} eq "SWITCH")) {
		EjsPushSwitch($e, $l, $var, $name, $env);
	} else {
		pidl "return ejs_panic(ejs, \"unhandled push type $l->{TYPE}\");\n";
	}
}

#############################################
# push a structure/union element at top level
sub EjsPushElementTop($$)
{
	my $e = shift;
	my $env = shift;
	my $l = $e->{LEVELS}[0];
	my $var = util::ParseExpr($e->{NAME}, $env);
	my $name = "\"$e->{NAME}\"";
	EjsPushElement($e, $l, $var, $name, $env);
}

###########################
# push a struct
sub EjsStructPush($$)
{
	my $name = shift;
	my $d = shift;
	my $env = GenerateStructEnv($d);
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const struct $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_push_struct_start(ejs, &v, name));\n";
        foreach my $e (@{$d->{ELEMENTS}}) {
		EjsPushElementTop($e, $env);
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
	my $have_default = 0;
	my $env = GenerateStructEnv($d);
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const union $name *r)\n{\n";
	pidl "\tNDR_CHECK(ejs_push_struct_start(ejs, &v, name));\n";
	pidl "switch (ejs->switch_var) {\n";
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e->{CASE} eq "default") {
			$have_default = 1;
		}
		pidl "$e->{CASE}:";
		if ($e->{TYPE} ne "EMPTY") {
			EjsPushElementTop($e, $env);
		}
		pidl "break;\n";
	}
	if (! $have_default) {
		pidl "default:";
		pidl "\treturn ejs_panic(ejs, \"Bad switch value\");";
	}
	pidl "}\nreturn NT_STATUS_OK;\n}\n";
}

###########################
# push a enum
sub EjsEnumPush($$)
{
	my $name = shift;
	my $d = shift;
	my $v = 0;
	# put the enum elements in the constants array
	foreach my $e (@{$d->{ELEMENTS}}) {
		my $el = $e;
		chomp $el;
		if ($el =~ /^(.*)=\s*(.*)\s*$/) {
			$el = $1;
			$v = $2;
		}
		$constants{$el} = $v;
		$v++;
	}
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const enum $name *r)\n{\n";
	pidl "\tunsigned e = *r;\n";
	pidl "\tNDR_CHECK(ejs_push_enum(ejs, v, name, &e));\n";
	pidl "\treturn NT_STATUS_OK;\n";
	pidl "}\n\n";
}

###########################
# push a bitmap
sub EjsBitmapPush($$)
{
	my $name = shift;
	my $d = shift;
	my $type_fn = $d->{BASE_TYPE};
	my($type_decl) = typelist::mapType($d->{BASE_TYPE});
	# put the bitmap elements in the constants array
	foreach my $e (@{$d->{ELEMENTS}}) {
		if ($e =~ /^(\w*)\s*(.*)\s*$/) {
			my $bname = $1;
			my $v = $2;
			$constants{$bname} = $v;
		}
	}
	pidl fn_prefix($d);
	pidl "NTSTATUS ejs_push_$name(struct ejs_rpc *ejs, struct MprVar *v, const char *name, const $type_decl *r)\n{\n";
	pidl "return ejs_push_$type_fn(ejs, v, name, r);\n";
	pidl "}\n";
}


###########################
# generate a structure push
sub EjsTypedefPush($)
{
	my $d = shift;
	return if (util::has_property($d, "noejs"));
	if ($d->{DATA}->{TYPE} eq 'STRUCT') {
		EjsStructPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'UNION') {
		EjsUnionPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'ENUM') {
		EjsEnumPush($d->{NAME}, $d->{DATA});
	} elsif ($d->{DATA}->{TYPE} eq 'BITMAP') {
		EjsBitmapPush($d->{NAME}, $d->{DATA});
	} else {
		warn "Unhandled push typedef $d->{NAME} of type $d->{DATA}->{TYPE}\n";
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
		EjsPushElementTop($e, $env);
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

###################
# handle a constant
sub EjsConst($)
{
    my $const = shift;
    $constants{$const->{NAME}} = $const->{VALUE};
}

#####################################################################
# parse the interface definitions
sub EjsInterface($)
{
	my($interface) = shift;
	my @fns = ();
	my $name = $interface->{NAME};

	%constants = ();

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

	foreach my $d (@{$interface->{CONSTS}}) {
		EjsConst($d);
	}

	pidl "void setup_ejs_$name(void)\n";
	pidl "{\n";
	foreach (@fns) {
		pidl "\tejsDefineCFunction(-1, \"dcerpc_$_\", ejs_$_, NULL, MPR_VAR_SCRIPT_HANDLE);\n";
	}
	pidl "}\n\n";

	pidl "void setup_ejs_constants_$name(int eid)\n";
	pidl "{\n";
	foreach my $v (keys %constants) {
		my $value = $constants{$v};
		if (substr($value, 0, 1) eq "\"") {
			pidl "\tejs_set_constant_string(eid, \"$v\", $value);\n";
		} else {
			pidl "\tejs_set_constant_int(eid, \"$v\", $value);\n";
		}
	}
	pidl "}\n";
}

#####################################################################
# parse a parsed IDL into a C header
sub Parse($$)
{
    my($ndr,$hdr) = @_;
    
    my $ejs_hdr = $hdr;
    $ejs_hdr =~ s/.h$/_ejs.h/;
    $res = "";
    pidl "
/* EJS wrapper functions auto-generated by pidl */
#include \"includes.h\"
#include \"lib/ejs/ejs.h\"
#include \"scripting/ejs/ejsrpc.h\"
#include \"librpc/gen_ndr/ndr_misc_ejs.h\"
#include \"$hdr\"
#include \"$ejs_hdr\"

";
    foreach my $x (@{$ndr}) {
	    if ($x->{TYPE} eq "INTERFACE") {
		    ($x->{TYPE} eq "INTERFACE") && EjsInterface($x);
	    }
    }

    return $res;
}

1;
