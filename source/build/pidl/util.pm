###################################################
# utility functions to support pidl
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package util;

#####################################################################
# load a data structure from a file (as saved with SaveStructure)
sub LoadStructure($)
{
	my $f = shift;
	my $contents = FileLoad($f);
	defined $contents || return undef;
	return eval "$contents";
}

use strict;

#####################################################################
# flatten an array of arrays into a single array
sub FlattenArray2($) 
{ 
    my $a = shift;
    my @b;
    for my $d (@{$a}) {
	for my $d1 (@{$d}) {
	    push(@b, $d1);
	}
    }
    return \@b;
}

#####################################################################
# flatten an array of arrays into a single array
sub FlattenArray($) 
{ 
    my $a = shift;
    my @b;
    for my $d (@{$a}) {
	for my $d1 (@{$d}) {
	    push(@b, $d1);
	}
    }
    return \@b;
}

#####################################################################
# flatten an array of hashes into a single hash
sub FlattenHash($) 
{ 
    my $a = shift;
    my %b;
    for my $d (@{$a}) {
	for my $k (keys %{$d}) {
	    $b{$k} = $d->{$k};
	}
    }
    return \%b;
}


#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
    if (ref($v) eq "ARRAY") {
	foreach my $i (0 .. $#{$v}) {
	    CleanData($v->[$i]);
	    if (ref($v->[$i]) eq "ARRAY" && $#{$v->[$i]}==-1) { 
		    $v->[$i] = undef; 
		    next; 
	    }
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
	    if (ref($v->{$x}) eq "ARRAY" && $#{$v->{$x}}==-1) { delete($v->{$x}); next; }
	}
    }
}


#####################################################################
# return the modification time of a file
sub FileModtime($)
{
    my($filename) = shift;
    return (stat($filename))[9];
}


#####################################################################
# read a file into a string
sub FileLoad($)
{
    my($filename) = shift;
    local(*INPUTFILE);
    open(INPUTFILE, $filename) || return undef;
    my($saved_delim) = $/;
    undef $/;
    my($data) = <INPUTFILE>;
    close(INPUTFILE);
    $/ = $saved_delim;
    return $data;
}

#####################################################################
# write a string into a file
sub FileSave($$)
{
    my($filename) = shift;
    my($v) = shift;
    local(*FILE);
    open(FILE, ">$filename") || die "can't open $filename";    
    print FILE $v;
    close(FILE);
}

#####################################################################
# return a filename with a changed extension
sub ChangeExtension($$)
{
    my($fname) = shift;
    my($ext) = shift;
    if ($fname =~ /^(.*)\.(.*?)$/) {
	return "$1$ext";
    }
    return "$fname$ext";
}

#####################################################################
# a dumper wrapper to prevent dependence on the Data::Dumper module
# unless we actually need it
sub MyDumper($)
{
	require Data::Dumper;
	my $s = shift;
	return Data::Dumper::Dumper($s);
}

#####################################################################
# save a data structure into a file
sub SaveStructure($$)
{
	my($filename) = shift;
	my($v) = shift;
	FileSave($filename, MyDumper($v));
}

#####################################################################
# find an interface in an array of interfaces
sub get_interface($$)
{
	my($if) = shift;
	my($n) = shift;

	foreach(@{$if}) {
		if($_->{NAME} eq $n) { return $_; }
	}
	
	return 0;
}

#####################################################################
# see if a pidl property list contains a given property
sub has_property($$)
{
	my($e) = shift;
	my($p) = shift;

	if (!defined $e->{PROPERTIES}) {
		return undef;
	}

	return $e->{PROPERTIES}->{$p};
}

#####################################################################
# see if a pidl property matches a value
sub property_matches($$$)
{
	my($e) = shift;
	my($p) = shift;
	my($v) = shift;

	if (!defined has_property($e, $p)) {
		return undef;
	}

	if ($e->{PROPERTIES}->{$p} =~ /$v/) {
		return 1;
	}

	return undef;
}

my %enum_list;

sub register_enum($$)
{
	my $enum = shift;
	my $name = shift;
	$enum_list{$name} = $enum;
}

sub is_enum($)
{
	my $name = shift;
	return defined $enum_list{$name}
}

sub get_enum($)
{
	my $name = shift;
	return $enum_list{$name};
}

sub enum_type_decl($)
{
	my $enum = shift;
	return "enum $enum->{TYPE}";
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

my %bitmap_list;

sub register_bitmap($$)
{
	my $bitmap = shift;
	my $name = shift;
	$bitmap_list{$name} = $bitmap;
}

sub is_bitmap($)
{
	my $name = shift;
	return defined $bitmap_list{$name};
}

sub get_bitmap($)
{
	my $name = shift;
	return $bitmap_list{$name};
}

sub bitmap_type_fn($)
{
	my $bitmap = shift;

	if (util::has_property($bitmap->{PARENT}, "bitmap8bit")) {
		return "uint8";
	} elsif (util::has_property($bitmap->{PARENT}, "bitmap16bit")) {
		return "uint16";
	} elsif (util::has_property($bitmap->{PARENT}, "bitmap64bit")) {
		return "uint64";
	}
	return "uint32";
}

sub bitmap_type_decl($)
{
	my $bitmap = shift;
	return map_type(bitmap_type_fn($bitmap));
}


# determine if an element is a pass-by-reference structure
sub is_ref_struct($)
{
	my $e = shift;
	if (!is_scalar_type($e->{TYPE}) &&
	    has_property($e, "ref")) {
		return 1;
	}
	return 0;
}

# determine the array size (size_is() or ARRAY_LEN)
sub array_size($)
{
	my $e = shift;
	my $size = has_property($e, "size_is");
	if ($size) {
		return $size;
	}
	$size = $e->{ARRAY_LEN};
	if ($size) {
		return $size;
	}
	return undef;
}

# return 1 if the string is a C constant
sub is_constant($)
{
	my $s = shift;
	if (defined $s && $s =~ /^\d/) {
		return 1;
	}
	return 0;
}

# return 1 if this is a fixed array
sub is_fixed_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	if (defined $len && is_constant($len)) {
		return 1;
	}
	return 0;
}

# return 1 if this is a inline array
sub is_inline_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	if (is_fixed_array($e) ||
	    defined $len && $len ne "*") {
		return 1;
	}
	return 0;
}

# return a "" quoted string, unless already quoted
sub make_str($)
{
	my $str = shift;
	if (substr($str, 0, 1) eq "\"") {
		return $str;
	}
	return "\"" . $str . "\"";
}


# provide mappings between IDL base types and types in our headers
my %type_mappings = 
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
     "uint64"       => "uint64_t",
     "dlong"        => "int64_t",
     "udlong"       => "uint64_t",
     "hyper"        => "uint64_t",
     "NTTIME_1sec"  => "NTTIME",
     "NTTIME_hyper" => "NTTIME",
     "ipv4address"  => "const char *"
     );

# map from a IDL type to a C header type
sub map_type($)
{
	my $name = shift;
	if (my $ret = $type_mappings{$name}) {
		return $ret;
	}
	return $name;
}

1;

