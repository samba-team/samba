###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Typelist;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(hasType getType mapType scalar_is_reference);
use vars qw($VERSION);
$VERSION = '0.01';

use Parse::Pidl::Util qw(has_property);
use strict;

my %typedefs = ();

my @reference_scalars = (
	"string", "string_array", "nbt_string", 
	"wrepl_nbt_name", "ipv4address"
);

# a list of known scalar types
my $scalars = {
	# 0 byte types
	"void"		=> {
				C_TYPE		=> "void",
			},

	# 1 byte types
	"char"		=> {
				C_TYPE		=> "char",
			},
	"int8"		=> {
				C_TYPE		=> "int8_t",
			},
	"uint8"		=> {
				C_TYPE		=> "uint8_t",
			},

	# 2 byte types
	"int16"		=> {
				C_TYPE		=> "int16_t",
			},
	"uint16"	=> {	C_TYPE		=> "uint16_t",
			},

	# 4 byte types
	"int32"		=> {
				C_TYPE		=> "int32_t",
			},
	"uint32"	=> {	C_TYPE		=> "uint32_t",
			},

	# 8 byte types
	"hyper"		=> {
				C_TYPE		=> "uint64_t",
			},
	"dlong"		=> {
				C_TYPE		=> "int64_t",
			},
	"udlong"	=> {
				C_TYPE		=> "uint64_t",
			},
	"udlongr"	=> {
				C_TYPE		=> "uint64_t",
			},
	# assume its a 8 byte type, but cope with either
	"pointer"	=> {
				C_TYPE		=> "void*",
			},

	# DATA_BLOB types
	"DATA_BLOB"	=> {
				C_TYPE		=> "DATA_BLOB",
			},

	# string types
	"string"	=> {
				C_TYPE		=> "const char *",
			},
	"string_array"	=> {
				C_TYPE		=> "const char **",
			},

	# time types
	"time_t"	=> {
				C_TYPE		=> "time_t",
			},
	"NTTIME"	=> {
				C_TYPE		=> "NTTIME",
			},
	"NTTIME_1sec"	=> {
				C_TYPE		=> "NTTIME",
			},
	"NTTIME_hyper"	=> {
				C_TYPE		=> "NTTIME",
			},


	# error code types
	"WERROR"	=> {
				C_TYPE		=> "WERROR",
			},
	"NTSTATUS"	=> {
				C_TYPE		=> "NTSTATUS",
			},
	"COMRESULT" => { 
				C_TYPE		=> "COMRESULT",
			},

	# special types
	"nbt_string"	=> {
				C_TYPE		=> "const char *",
			},
	"wrepl_nbt_name"=> {
				C_TYPE		=> "struct nbt_name *",
			},
	"ipv4address"	=> {
				C_TYPE		=> "const char *",
			}
};

# map from a IDL type to a C header type
sub mapScalarType($)
{
	my $name = shift;

	# it's a bug when a type is not in the list
	# of known scalars or has no mapping
	return $typedefs{$name}->{DATA}->{C_TYPE} if defined($typedefs{$name}) and defined($typedefs{$name}->{DATA}->{C_TYPE});

	die("Unknown scalar type $name");
}

sub addType($)
{
	my $t = shift;
	$typedefs{$t->{NAME}} = $t;
}

sub getType($)
{
	my $t = shift;
	return undef if not hasType($t);
	return $typedefs{$t};
}

sub typeIs($$)
{
	my $t = shift;
	my $tt = shift;

	return 1 if (hasType($t) and getType($t)->{DATA}->{TYPE} eq $tt);
	return 0;
}

sub hasType($)
{
	my $t = shift;
	return 1 if defined($typedefs{$t});
	return 0;
}

sub is_scalar($)
{
	my $type = shift;

	return 0 unless(hasType($type));

	if (my $dt = getType($type)->{DATA}->{TYPE}) {
		return 1 if ($dt eq "SCALAR" or $dt eq "ENUM" or $dt eq "BITMAP");
	}

	return 0;
}

sub scalar_is_reference($)
{
	my $name = shift;
	
	return 1 if (grep(/^$name$/, @reference_scalars));
	return 0;
}

sub RegisterScalars()
{
	foreach my $k (keys %{$scalars}) {
		$typedefs{$k} = {
			NAME => $k,
			TYPE => "TYPEDEF",
			DATA => $scalars->{$k}
		};
		$typedefs{$k}->{DATA}->{TYPE} = "SCALAR";
		$typedefs{$k}->{DATA}->{NAME} = $k;
	}
}

my $aliases = {
	"DWORD" => "uint32",
	"int" => "int32",
	"WORD" => "uint16",
	"char" => "uint8",
	"long" => "int32",
	"short" => "int16",
	"HYPER_T" => "hyper",
	"HRESULT" => "COMRESULT",
};

sub RegisterAliases()
{
	foreach my $k (keys %{$aliases}) {
		$typedefs{$k} = $typedefs{$aliases->{$k}};
	}
}

sub enum_type_fn($)
{
	my $enum = shift;
	if (has_property($enum->{PARENT}, "enum8bit")) {
		return "uint8";
	} elsif (has_property($enum->{PARENT}, "v1_enum")) {
		return "uint32";
	}
	return "uint16";
}

sub bitmap_type_fn($)
{
	my $bitmap = shift;

	if (has_property($bitmap, "bitmap8bit")) {
		return "uint8";
	} elsif (has_property($bitmap, "bitmap16bit")) {
		return "uint16";
	} elsif (has_property($bitmap, "bitmap64bit")) {
		return "hyper";
	}
	return "uint32";
}

sub mapType($)
{
	my $t = shift;
	die("Undef passed to mapType") unless defined($t);
	my $dt;

	unless ($dt or ($dt = getType($t))) {
		# Best guess
		return "struct $t";
	}
	return mapScalarType($t) if ($dt->{DATA}->{TYPE} eq "SCALAR");
	return "enum $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "ENUM");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "STRUCT");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "INTERFACE");
	return "union $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "UNION");

	if ($dt->{DATA}->{TYPE} eq "BITMAP") {
		return mapScalarType(bitmap_type_fn($dt->{DATA}));
	}

	die("Unknown type $dt->{DATA}->{TYPE}");
}

sub LoadIdl($)
{
	my $idl = shift;

	foreach my $x (@{$idl}) {
		next if $x->{TYPE} ne "INTERFACE";

		# DCOM interfaces can be types as well
		addType({
			NAME => $x->{NAME},
			TYPE => "TYPEDEF",
			DATA => $x
			}) if (has_property($x, "object"));

		foreach my $y (@{$x->{DATA}}) {
			addType($y) if (
				$y->{TYPE} eq "TYPEDEF" 
			     or $y->{TYPE} eq "DECLARE");
		}
	}
}

RegisterScalars();
RegisterAliases();

1;
