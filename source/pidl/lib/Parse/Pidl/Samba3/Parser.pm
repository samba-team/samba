###################################################
# Samba3 NDR parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Parser;

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);
use Parse::Pidl::Samba3::Types qw(DeclShort DeclLong InitType DissectType);

use vars qw($VERSION);
$VERSION = '0.01';

my $res = "";
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $res .= $tabs.(shift)."\n"; }
sub fatal($$) { my ($e,$s) = @_; die("$e->{FILE}:$e->{LINE}: $s\n"); }

#TODO:
# - Different scalars / buffers functions for arrays + unions
# - Register own types with Types::AddType()
# - Find external types somehow?

sub DeclareArrayVariables($)
{
	my $es = shift;

	foreach my $e (@$es) {
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "ARRAY") {
				pidl "uint32 i_$e->{NAME}_$l->{LEVEL_INDEX};";
			}
		}
	}
}

sub ParseElementLevelData($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	pidl "if (!".DissectType($e, $l, $varname).")";
	pidl "\treturn False;";
}

sub ParseElementLevelArray($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	my $i = "i_$e->{NAME}_$l->{LEVEL_INDEX}";
	pidl "for ($i=0; $i<".ParseExpr("length_$e->{NAME}", $env) .";$i++) {";
	indent;
	ParseElementLevel($e,$nl,$env,$varname."[$i]");
	deindent;
	pidl "}";
}

sub ParseElementLevelSwitch($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	pidl "if (!prs_uint32(\"level\", ps, depth, " . ParseExpr("level_$e->{NAME}", $env) . ", ps, depth))";
	pidl "\treturn False;";
	pidl "";

	ParseElementLevel($e,$nl,$env,$varname);
}

sub ParseElementLevelPtr($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	if ($l->{POINTER_TYPE} eq "relative") {
		fatal($e, "relative pointers not supported for Samba 3");
	}

	pidl "if (!prs_uint32(\"ptr_$e->{NAME}\",ps,depth,&" . ParseExpr("ptr_$e->{NAME}", $env) . ", ps, depth))";
	pidl "\treturn False;";
	pidl "";
	
	pidl "if (" . ParseExpr("ptr_$e->{NAME}", $env) . ") {";
	indent;
	ParseElementLevel($e,$nl,$env,$varname);
	deindent;
	pidl "}";
}

sub ParseElementLevelSubcontext($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	fatal($e, "subcontext() not supported for Samba 3");
}

sub ParseElementLevel($$$$)
{
	my ($e,$l,$env,$varname) = @_;

	{
		DATA => \&ParseElementLevelData,
		SUBCONTEXT => \&ParseElementLevelSubcontext,
		POINTER => \&ParseElementLevelPtr,
		SWITCH => \&ParseElementLevelSwitch,
		ARRAY => \&ParseElementLevelArray
	}->{$l->{TYPE}}->($e,$l,GetNextLevel($e,$l),$env,$varname);
}

sub ParseElement($$)
{
	my ($e,$env) = @_;

	ParseElementLevel($e, $e->{LEVELS}[0], $env, ParseExpr($e->{NAME}, $env));
}

sub InitLevel($$$$);

sub InitLevel($$$$)
{
	my ($e,$l,$varname,$env) = @_;

	if ($l->{TYPE} eq "POINTER") {
		pidl "if ($varname) {";
		indent;
		pidl ParseExpr("ptr_$e->{NAME}", $env) . " = 1;";
		InitLevel($e, GetNextLevel($e,$l), $varname, $env);
		deindent;
		pidl "} else {";
		pidl "\t" . ParseExpr("ptr_$e->{NAME}", $env) . " = 0;";
		pidl "}";
	} elsif ($l->{TYPE} eq "ARRAY") {
		pidl "for (i = 0; i < " . ParseExpr("len_$e->{NAME}", $env) . "; i++) {";
		indent;
		InitLevel($e, GetNextLevel($e,$l), $varname."[i]", $env);
		deindent;
		pidl "}";
	} elsif ($l->{TYPE} eq "DATA") {
		pidl InitType($e, $l, $varname, $varname);
	} elsif ($l->{TYPE} eq "SWITCH") {
		InitLevel($e, GetNextLevel($e,$l), $varname, $env);
	}
}

sub CreateStruct($$$$)
{
	my ($fn,$s,$es,$a) = @_;

	my $args = "";
	foreach my $e (@$es) {
		$args .= ", " . DeclLong($_);
	}

	my $env = {};
	foreach my $e (@$es) {
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "DATA") {
				$env->{"$e->{NAME}"} = $e->{"v->$e->{NAME}"};
			} elsif ($l->{TYPE} eq "POINTER") {
				$env->{"ptr_$e->{NAME}"} = $e->{"v->ptr_$e->{NAME}"};
			} elsif ($l->{TYPE} eq "SWITCH") {
				$env->{"level_$e->{NAME}"} = $e->{"v->level_$e->{NAME}"};
			} 
		}
	}

	pidl "BOOL init_$fn($s *v$args)";
	pidl "{";
	indent;
	pidl "DEBUG(5,(\"init_$fn\\n\"));";
	pidl "";
	# Call init for all arguments
	foreach (@$es) {
		InitLevel($_, $_->{LEVELS}[0], ParseExpr($_->{NAME}, $env), $env);
		pidl "";
	}
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
	
	pidl "BOOL $fn(const char *desc, $s *v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($es);
	pidl "if (v == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "prs_debug(ps, depth, desc, \"$fn\");";
	pidl "depth++;";
	if ($a > 0) {
		pidl "if (!prs_align(ps, $a))";
		pidl "\treturn False;";
		pidl "";
	}

	foreach (@$es) {
		ParseElement($_, $env);
		pidl "";
	}

	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
}

sub ParseStruct($$$)
{
	my ($if,$s,$n) = @_;

	my $fn = "$if->{NAME}_io_$n";
	my $sn = uc("$if->{NAME}_$n");

	CreateStruct($fn, $sn, $s->{ELEMENTS}, $s->{ALIGN});
}

sub ParseUnion($$$)
{
	my ($if,$u,$n) = @_;

	my $fn = "$if->{NAME}_io_$n";
	my $sn = uc("$if->{NAME}_$n");

	pidl "BOOL $fn(const char *desc, $sn* v, uint32 level, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	DeclareArrayVariables($u->{ELEMENTS});
	pidl "if (!prs_align(ps, $u->{ALIGN}))";
	pidl "\treturn False;";
	pidl "";

	pidl "switch (level) {";
	indent;

	foreach (@{$u->{ELEMENTS}}) {
		pidl "$_->{CASE}:";
		indent;
		pidl "depth++;";
		ParseElement($_, {});
		deindent;
		pidl "depth--;";
		pidl "break";
		pidl "";
	}

	deindent;
	pidl "}";
	pidl "";
	pidl "return True;";
	deindent;
	pidl "}";
}

sub ParseFunction($$)
{
	my ($if,$fn) = @_;

	my @in = ();
	my @out = ();

	foreach (@{$fn->{ELEMENTS}}) {
		push (@in, $_) if (grep(/in/, @{$_->{DIRECTION}}));
		push (@out, $_) if (grep(/out/, @{$_->{DIRECTION}}));
	}

	if (defined($fn->{RETURN_TYPE})) {
		push (@out, { 
			NAME => "status", 
			TYPE => $fn->{RETURN_TYPE},
			LEVELS => [
				{
					TYPE => "DATA",
					DATA_TYPE => $fn->{RETURN_TYPE}
				}
			]
		} );
	}

	CreateStruct("$if->{NAME}_io_q_$fn->{NAME}", uc("$if->{NAME}_q_$fn->{NAME}"), \@in, 0);
	CreateStruct("$if->{NAME}_io_r_$fn->{NAME}", uc("$if->{NAME}_r_$fn->{NAME}"), \@out, 0);
}

sub ParseInterface($)
{
	my $if = shift;

	# Structures first 
	pidl "/* $if->{NAME} structures */";
	foreach (@{$if->{TYPEDEFS}}) {
		ParseStruct($if, $_->{DATA}, $_->{NAME}) if ($_->{TYPE} eq "STRUCT");
		ParseUnion($if, $_->{DATA}, $_->{NAME}) if ($_->{TYPE} eq "UNION");
	}

	pidl "/* $if->{NAME} functions */";
	ParseFunction($if, $_) foreach (@{$if->{FUNCTIONS}});
}

sub Parse($$)
{
	my($ndr,$filename) = @_;

	$tabs = "";
	$res = "";

	pidl "/*";
	pidl " * Unix SMB/CIFS implementation.";
	pidl " * parser auto-generated by pidl. DO NOT MODIFY!";
	pidl " */";
	pidl "";
	pidl "#include \"includes.h\"";
	pidl "";
	pidl "#undef DBGC_CLASS";
	pidl "#define DBGC_CLASS DBGC_RPC_PARSE";
	pidl "";

	foreach (@$ndr) {
		ParseInterface($_) if ($_->{TYPE} eq "INTERFACE");
	}

	return $res;
}

1;
