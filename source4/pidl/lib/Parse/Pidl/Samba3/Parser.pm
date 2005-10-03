###################################################
# Samba3 NDR parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Parser;

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);
use Parse::Pidl::Samba3::Util qw(MapSamba3Type);

use vars qw($VERSION);
$VERSION = '0.01';

my $res = "";
my $tabs = "";
sub indent() { $tabs.="\t"; }
sub deindent() { $tabs = substr($tabs, 1); }
sub pidl($) { $res .= $tabs.(shift)."\n"; }
sub fatal($$) { my ($e,$s) = @_; die("$e->{FILE}:$e->{LINE}: $s\n"); }

sub ParseElementLevelData($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	#FIXME: This only works for scalar types
	pidl "if (!prs_$l->{DATA_TYPE}(\"$e->{NAME}\", ps, depth, &$varname))";
	pidl "\treturn False;";
	pidl "";
}

sub ParseElementLevelArray($$$$$)
{
	my ($e,$l,$nl,$env,$varname) = @_;

	#FIXME
	pidl "for (i=0; i<".ParseExpr("length_$e->{NAME}", $env) .";i++) {";
	indent;
	ParseElementLevel($e,$nl,$env,"$varname\[i]");
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

	# No top-level ref pointers for Samba 3
	return if ($l->{POINTER_TYPE} eq "ref" and $l->{LEVEL} eq "TOP");

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

sub CreateStruct($$$)
{
	my ($fn,$s,$es) = @_;

	my $args = "";
	foreach my $e (@$es) {
		$args .= ", " . MapSamba3Type($_);
	}

	pidl "BOOL init_$fn($s *v$args)";
	pidl "{";
	indent;
	pidl "DEBUG(5,(\"init_$fn\\n\"));";
	# Call init for all arguments
	foreach my $e (@$es) {
		foreach my $l (@{$e->{LEVELS}}) {
			#FIXME
		}
	}
	pidl "return True;";
	deindent;
	pidl "}";
	pidl "";
	
	pidl "BOOL $fn(const char *desc, $s *v, prs_struct *ps, int depth)";
	pidl "{";
	indent;
	pidl "if (v == NULL)";
	pidl "\treturn False;";
	pidl "";
	pidl "prs_debug(ps, depth, desc, \"$fn\");";
	pidl "depth++;";
	pidl "if (!prs_align(ps))";
	pidl "\treturn False;";
	pidl "";

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

	ParseElement($_, $env) foreach (@$es);

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

	CreateStruct($fn, $sn, $s->{ELEMENTS});
}

sub ParseUnion($$$)
{
	my ($if,$u,$n) = @_;

	my $fn = "$if->{NAME}_io_$n";
	my $sn = uc("$if->{NAME}_$n");

	pidl "BOOL $fn(const char *desc, $sn* v, uint32 level, prs_struct *ps, int depth)";
	pidl "{";
	indent;
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

	CreateStruct("$if->{NAME}_io_q_$fn->{NAME}", uc("$if->{NAME}_q_$fn->{NAME}"), \@in);
	CreateStruct("$if->{NAME}_io_r_$fn->{NAME}", uc("$if->{NAME}_r_$fn->{NAME}"), \@out);
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
