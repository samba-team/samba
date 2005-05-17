###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package typelist;

use strict;

my %typedefs = ();

# a list of known scalar types
my $scalars = {
	# 0 byte types
	"void"		=> {
				C_TYPE		=> "void",
				NDR_ALIGN	=> 0
			},

	# 1 byte types
	"char"		=> {
				C_TYPE		=> "char",
				NDR_ALIGN	=> 1
			},
	"int8"		=> {
				C_TYPE		=> "int8_t",
				NDR_ALIGN	=> 1
			},
	"uint8"		=> {
				C_TYPE		=> "uint8_t",
				NDR_ALIGN	=> 1
			},

	# 2 byte types
	"int16"		=> {
				C_TYPE		=> "int16_t",
				NDR_ALIGN	=> 2
			},
	"uint16"	=> {	C_TYPE		=> "uint16_t",
				NDR_ALIGN	=> 2
			},

	# 4 byte types
	"int32"		=> {
				C_TYPE		=> "int32_t",
				NDR_ALIGN	=> 4
			},
	"uint32"	=> {	C_TYPE		=> "uint32_t",
				NDR_ALIGN	=> 4
			},

	# 8 byte types
	"int64"		=> {
				C_TYPE		=> "int64_t",
				NDR_ALIGN	=> 8
			},
	"hyper"		=> {
				C_TYPE		=> "uint64_t",
				NDR_ALIGN	=> 8
			},
	"dlong"		=> {
				C_TYPE		=> "int64_t",
				NDR_ALIGN	=> 4
			},
	"udlong"	=> {
				C_TYPE		=> "uint64_t",
				NDR_ALIGN	=> 4
			},
	"udlongr"	=> {
				C_TYPE		=> "uint64_t",
				NDR_ALIGN	=> 4
			},

	# DATA_BLOB types
	"DATA_BLOB"	=> {
				C_TYPE		=> "DATA_BLOB",
				NDR_ALIGN	=> 4
			},

	# string types
	"string"	=> {
				C_TYPE		=> "const char *",
				NDR_ALIGN	=> 4 #???
			},
	"string_array"	=> {
				C_TYPE		=> "const char **",
				NDR_ALIGN	=> 4 #???
			},

	# time types
	"time_t"	=> {
				C_TYPE		=> "time_t",
				NDR_ALIGN	=> 4
			},
	"NTTIME"	=> {
				C_TYPE		=> "NTTIME",
				NDR_ALIGN	=> 4
			},
	"NTTIME_1sec"	=> {
				C_TYPE		=> "NTTIME",
				NDR_ALIGN	=> 4
			},
	"NTTIME_hyper"	=> {
				C_TYPE		=> "NTTIME",
				NDR_ALIGN	=> 8
			},


	# error code types
	"WERROR"	=> {
				C_TYPE		=> "WERROR",
				NDR_ALIGN	=> 4
			},
	"NTSTATUS"	=> {
				C_TYPE		=> "NTSTATUS",
				NDR_ALIGN	=> 4
			},

	# special types
	"nbt_string"	=> {
				C_TYPE		=> "const char *",
				NDR_ALIGN	=> 4 #???
			},
	"ipv4address"	=> {
				C_TYPE		=> "const char *",
				NDR_ALIGN	=> 4
			}
};

# map from a IDL type to a C header type
sub mapScalarType($)
{
	my $name = shift;

	# it's a bug when a type is not in the list
	# of known scalars or has no mapping
	return $scalars->{$name}{C_TYPE} if defined($scalars->{$name}) and defined($scalars->{$name}{C_TYPE});

	die("Unknown scalar type $name");
}

sub getScalarAlignment($)
{
	my $name = shift;

	# it's a bug when a type is not in the list
	# of known scalars or has no mapping
	return $scalars->{$name}{NDR_ALIGN} if defined($scalars->{$name}) and defined($scalars->{$name}{NDR_ALIGN});

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
	return undef unless(defined($typedefs{$t}));
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

sub RegisterScalars()
{
	foreach my $k (keys %{$scalars}) {
		$typedefs{$k} = {
			NAME => $k,
			TYPE => "TYPEDEF",
			DATA => {
				TYPE => "SCALAR",
				NAME => $k
			}
		};
	}
}

sub enum_type_fn($)
{
	my $enum = shift;
	if (util::has_property($enum->{PARENT}, "enum8bit")) {
		return "uint8";
	} elsif (util::has_property($enum->{PARENT}, "v1_enum")) {
		return "uint32";
	}
	return "uint16";
}

sub bitmap_type_fn($)
{
	my $bitmap = shift;

	if (util::has_property($bitmap, "bitmap8bit")) {
		return "uint8";
	} elsif (util::has_property($bitmap, "bitmap16bit")) {
		return "uint16";
	} elsif (util::has_property($bitmap, "bitmap64bit")) {
		return "hyper";
	}
	return "uint32";
}

sub mapType($)
{
	my $e = shift;
	my $dt;

	if ($e->{TYPE} eq "ENUM" or $e->{TYPE} eq "BITMAP") {
		$dt = getType($e->{PARENT}->{NAME});
	}
	
	unless ($dt or $dt = getType($e->{TYPE})) {
		# Best guess
		return "struct $e->{TYPE}";
	}
	return mapScalarType($e->{TYPE}) if ($dt->{DATA}->{TYPE} eq "SCALAR");
	return "enum $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "ENUM");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "STRUCT");
	return "struct $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "INTERFACE");
	return "union $dt->{NAME}" if ($dt->{DATA}->{TYPE} eq "UNION");
	return mapScalarType(bitmap_type_fn($dt->{DATA})) if ($dt->{DATA}->{TYPE} eq "BITMAP");

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
			}) if (util::has_property($x, "object"));

		foreach my $y (@{$x->{DATA}}) {
			addType($y) if (
				$y->{TYPE} eq "TYPEDEF" 
			 or $y->{TYPE} eq "DECLARE");
		}
	}
}

RegisterScalars();

1;
