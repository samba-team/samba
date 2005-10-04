###################################################
# Samba3 type-specific declarations / initialization / marshalling
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Types;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(DeclShort DeclLong InitType DissectType AddType);

use strict;
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);

use vars qw($VERSION);
$VERSION = '0.01';

# TODO: Find external types somehow?

sub warning($$) { my ($e,$s) = @_; print STDERR "$e->{FILE}:$e->{LINE}: $s\n"; }

sub init_scalar($$$$)
{
	my ($e,$l,$n,$v) = @_;

	return "$n = $v;";
}

sub dissect_scalar($$$)
{
	my ($e,$l,$n) = @_;

	my $t = lc($e->{TYPE});
	
	return "prs_$t(\"$e->{NAME}\", ps, depth, &$n)";
}

sub decl_string($)
{
	my $e = shift;

	# FIXME: More intelligent code here - select between UNISTR2 and other
	# variants
	return "UNISTR2";
}

sub init_string($$$$)
{
	my ($e,$l,$n,$v) = @_;
	
	return "init_unistr2(&$n, $v, UNI_FLAGS_NONE);";
}

sub dissect_string($$$)
{
	my ($e,$l,$n) = @_;

	return "prs_unistr2(True, \"$e->{NAME}\", ps, depth, &n)";
}

sub init_uuid($$$$)
{
	my ($e,$l,$n,$v) = @_;

	return "";
}

sub dissect_uuid($$$)
{
	my ($e,$l,$n) = @_;

	return "smb_io_uuid(\"$e->{NAME}\", &$n, ps, depth)";
}

my $known_types = 
{
	uint8 => 
	{
		DECL => "uint8",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	uint16 => 
	{
		DECL => "uint16",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	uint32 => 
	{
		DECL => "uint32",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	string => 
	{
		DECL => \&decl_string,
		INIT => \&init_string,
		DISSECT => \&dissect_string,
	},
	NTSTATUS => 
	{
		DECL => "NTSTATUS",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	WERROR => 
	{
		DECL => "WERROR",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	GUID => 
	{
		DECL => "struct uuid",
		INIT => \&init_uuid,
		DISSECT => \&dissect_uuid,
	}
};

sub AddType($$)
{
	my ($t,$d) = @_;

	warn("Reregistering type $t") if (defined($known_types->{$t}));

	$known_types->{$t} = $d;
}

sub GetType($)
{
	my $e = shift;

	my $t = $known_types->{$e->{TYPE}};

	if (not $t) {
		warning($e, "Can't declare unknown type $e->{TYPE}");
		return undef;
	}

	# DECL can be a function
	if (ref($t->{DECL}) eq "CODE") {
		return $t->{DECL}->($e);
	} else {
		return $t->{DECL};
	}
}

# Return type without special stuff, as used in 
# struct declarations
sub DeclShort($)
{
	my $e = shift;

	my $t = GetType($e);
	return undef if not $t;
	
	return "$t $e->{NAME}";
}

sub DeclLong($)
{
	my $e = shift;

	my $t = GetType($e);

	return undef if not $t;

	my $ptrs = "";

	foreach my $l (@{$e->{LEVELS}}) {
		($ptrs.="*") if ($l->{TYPE} eq "POINTER");
	}
	
	return "$t $ptrs$e->{NAME}";
}

sub InitType($$$$)
{
	my ($e, $l, $varname, $value) = @_;

	my $t = $known_types->{$l->{DATA_TYPE}};

	if (not $t) {
		warning($e, "Don't know how to initialize type $l->{DATA_TYPE}");
		return undef;
	}

	# INIT can be a function
	if (ref($t->{INIT}) eq "CODE") {
		return $t->{INIT}->($e, $l, $varname, $value);
	} else {
		return $t->{INIT};
	}
}

sub DissectType($$$)
{
	my ($e, $l, $varname) = @_;

	my $t = $known_types->{$l->{DATA_TYPE}};

	if (not $t) {
		warning($e, "Don't know how to dissect type $l->{DATA_TYPE}");
		return undef;
	}

	# DISSECT can be a function
	if (ref($t->{DISSECT}) eq "CODE") {
		return $t->{DISSECT}->($e, $l, $varname);
	} else {
		return $t->{DISSECT};
	}
}

sub LoadTypes($)
{
	my $ndr = shift;
	foreach my $if (@{$ndr}) {
		next unless ($if->{TYPE} eq "INTERFACE");

		foreach my $td (@{$if->{TYPEDEFS}}) {
			AddType($td->{NAME}, {
				DECL => uc("$if->{NAME}_$td->{NAME}"),
				INIT => sub {
					my ($e,$l,$n,$v) = @_;
					return "init_$td->{NAME}(&$n/*FIXME:OTHER ARGS*/);";
				},
				DISSECT => sub {
					my ($e,$l,$n) = @_;

					return "$if->{NAME}_io_$td->{NAME}(\"$e->{NAME}\", &$n, ps, depth)";
				}
			});
		}
	}
}

1;
