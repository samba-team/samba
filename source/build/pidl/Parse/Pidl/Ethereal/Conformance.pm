###################################################
# parse an ethereal conformance file
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Ethereal::Conformance;

require Exporter;

@ISA = qw(Exporter);
@EXPORT_OK = qw(ReadConformance);

use strict;

use Parse::Pidl::Util qw(has_property);

sub handle_type($$$$$$$$)
{
	my ($data,$name,$dissectorname,$ft_type,$base_type,$mask,$valsstring,$alignment) = @_;

	$data->{types}->{$name} = {
		NAME => $name,
		DISSECTOR_NAME => $dissectorname,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		MASK => $mask,
		VALSSTRING => $valsstring,
		ALIGNMENT => $alignment
	};
}


sub handle_hf_rename($$$)
{
	my ($data,$old,$new) = @_;
	$data->{hf_renames}{$old} = $new;
}

sub handle_param_value($$$)
{
	my ($data,$dissector_name,$value) = @_;

	$data->{dissectorparams}->{$dissector_name} = $value;
}

sub handle_hf_field($$$$$$$$$)
{
	my ($data,$hf,$title,$filter,$ft_type,$base_type,$valsstring,$mask,$blurb) = @_;

	$data->{header_fields}->{$hf} = {
		HF => $hf,
		TITLE => $title,
		FILTER => $filter,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		VALSSTRING => $valsstring,
		MASK => $mask,
		BLURB => $blurb
	};
}

sub handle_strip_prefix($$)
{
	my ($data,$x) = @_;

	push (@{$data->{strip_prefixes}}, $x);
}

sub handle_noemit($$)
{
	my ($data,$type) = @_;

	$data->{noemit}->{$type} = 1;
}

sub handle_protocol($$$$$)
{
	my ($data, $name, $longname, $shortname, $filtername) = @_;

	$data->{protocols}->{$name} = {
		LONGNAME => $longname,
		SHORTNAME => $shortname,
		FILTERNAME => $filtername
	};
}

sub handle_fielddescription($$$)
{
	my ($data,$field,$desc) = @_;

	$data->{fielddescription}->{$field} = $desc;
}

my %field_handlers = (
	TYPE => \&handle_type,
	NOEMIT => \&handle_noemit, 
	PARAM_VALUE => \&handle_param_value, 
	HF_FIELD => \&handle_hf_field, 
	HF_RENAME => \&handle_hf_rename, 
	STRIP_PREFIX => \&handle_strip_prefix,
	PROTOCOL => \&handle_protocol,
	FIELD_DESCRIPTION => \&handle_fielddescription
);

sub ReadConformance($$)
{
	my ($f,$data) = @_;

	$data->{override} = "";

	my $incodeblock = 0;

	open(IN,"<$f") or return undef;

	my $ln = 0;

	foreach (<IN>) {
		$ln++;
		next if (/^#.*$/);
		next if (/^$/);

		s/[\r\n]//g;

		if ($_ eq "CODE START") {
			$incodeblock = 1;
			next;
		} elsif ($incodeblock and $_ eq "CODE END") {
			$incodeblock = 0;
			next;
		} elsif ($incodeblock) {
			$data->{override}.="$_\n";
			next;
		}

		my @fields = split(/ /);

		my $cmd = $fields[0];

		shift @fields;

		if (not defined($field_handlers{$cmd})) {
			print "$f:$ln: Warning: Unknown command `$cmd'\n";
			next;
		}
		
		$field_handlers{$cmd}($data, @fields);
	}

	close(IN);
}

1;
