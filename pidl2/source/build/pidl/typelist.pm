###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package typelist;

use strict;

my %typedefs = ();

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

sub RegisterPrimitives()
{
	my @primitives = (
		"char", "int8", "uint8", "short", "wchar_t", 
		"int16", "uint16", "long", "int32", "uint32", 
		"dlong", "udlong", "udlongr", "NTTIME", "NTTIME_1sec", 
		"time_t", "DATA_BLOB", "error_status_t", "WERROR", 
		"NTSTATUS", "boolean32", "unsigned32", "ipv4address", 
		"hyper", "NTTIME_hyper");
		
	foreach my $k (@primitives) {
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

# provide mappings between IDL base types and types in our headers
my %scalar_type_mappings = 
    (
     "int8"         => "int8_t",
     "uint8"        => "uint8_t",
     "short"        => "int16_t",
     "wchar_t"      => "uint16_t",
     "int16"        => "int16_t",
     "uint16"       => "uint16_t",
     "int32"        => "int32_t",
     "uint32"       => "uint32_t",
     "int64"        => "int64_t",
     "dlong"        => "int64_t",
     "udlong"       => "uint64_t",
     "udlongr"      => "uint64_t",
     "hyper"        => "uint64_t",
     "NTTIME"       => "NTTIME",
     "NTTIME_1sec"  => "NTTIME",
     "time_t"       => "time_t",
     "NTTIME_hyper" => "NTTIME",
     "NTSTATUS"     => "NTSTATUS",
     "WERROR"       => "WERROR",
     "DATA_BLOB"    => "DATA_BLOB",
     "ipv4address"  => "const char *",
     "nbt_string"   => "const char *"
     );

# map from a IDL type to a C header type
sub mapScalarType($)
{
	my $name = shift;
	die("Undef passed to mapScalarType") unless defined($name);
	if (defined($scalar_type_mappings{$name})) {
		return $scalar_type_mappings{$name};
	}
	die("Tried to map non-scalar type $name");
}

sub mapType($)
{
	my $t = shift;
	die("Undef passed to mapType") unless defined($t);
	my $dt;

	return "void" if ($t eq "void");
	return "const char *" if ($t =~ "string");

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
			}) if (util::has_property($x, "object"));

		foreach my $y (@{$x->{DATA}}) {
			addType($y) if (
				$y->{TYPE} eq "TYPEDEF" 
			     or $y->{TYPE} eq "DECLARE");
		}
	}
}

RegisterPrimitives();


1;
