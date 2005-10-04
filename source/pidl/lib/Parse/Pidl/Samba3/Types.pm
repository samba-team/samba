###################################################
# Samba3 common helper functions
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

	return "FIXME";
}

my $known_types = {
	uint8 => {
		DECL => "uint8",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	uint16 => {
		DECL => "uint16",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	uint32 => {
		DECL => "uint32",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	string => {
		DECL => \&decl_string,
		INIT => \&init_string,
		DISSECT => \&dissect_string,
	},
	NTSTATUS => {
		DECL => "NTSTATUS",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
	WERROR => {
		DECL => "WERROR",
		INIT => \&init_scalar,
		DISSECT => \&dissect_scalar,
	},
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

	return undef if not $t;

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

	return "$t $e->{NAME}";
}

sub InitType($$$$)
{
	my ($e, $l, $varname, $value) = @_;

	my $t = $known_types->{$l->{DATA_TYPE}};

	return undef if not $t;

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

	return undef if not $t;

	# DISSECT can be a function
	if (ref($t->{DISSECT}) eq "CODE") {
		return $t->{DISSECT}->($e, $l, $varname);
	} else {
		return $t->{DISSECT};
	}
}

1;
