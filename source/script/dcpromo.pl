#!/usr/bin/perl -w

###################################################
# package to generate samba ads configuration
# Copyright metze@samba.org 2004

# released under the GNU GPL

use strict;
use Data::Dumper;

sub print_options($$) {
	my $ads = shift;
	my $ctx = shift;
	my @arr;
	my $i;
	my $len;

	print "options:\n";

	@arr = @{$ctx};
	$len = $#arr;
	for($i = 0; $i <= $len; $i++) {
		my $val = $ctx->[$i];
		print "\t".$i.": ".$val->{TEXT}."\n";
	}

	print "choise []:";
}

sub read_option($$) {
	my $ads = shift;
	my $ctx = shift;
	my $val;

	$val = <STDIN>;

	return $val;
}

sub call_option($$$) {
	my $ads = shift;
	my $ctx = shift;
	my $switch = shift;
	my $val;
	my $funcref;

	$val = $ctx->[$switch];

	$funcref = $val->{ACTION};

	&$funcref($ads);
}

sub ask_option($$) {
	my $ads = shift;
	my $ctx = shift;
	my $ret;

	print_options($ads, $ctx);

	$ret = read_option($ads, $ctx);

	call_option($ads, $ctx, $ret);
}

sub create_ads_tree($) {
	my $ads = shift;

	print "Create ADS Domain:\n";
	print Dumper($ads);
}

sub do_new_domain_in_entire_structure($) {
	my $ads;
	my $domain_dns;
	my $domain_netbios;

	$ads->{NEW_DOMAIN} = 1;
	$ads->{NEW_FOREST} = 1;

	print "full dns name of the new domain []:";	
	$domain_dns = <STDIN>;
	chomp $domain_dns;
	$ads->{FULL_DNS_NAME} = $domain_dns;

	print "netbios name of the new domain []:";	
	$domain_netbios = <STDIN>;
	chomp $domain_netbios;
	$ads->{NETBIOS} = $domain_netbios;

	create_ads_tree($ads);
}

sub do_sub_domain_in_existing_structure($) {
	my $ads = shift;
	my $user_name;
	my $user_domain;
	my $user_password;
	my $top_dns;
	my $domain_dns;
	my $domain_netbios;
	my $db_folder;
	my $db_logs;
	my $sysvol_folder;
	my $admin_password1;
	my $admin_password2;

	$ads->{NEW_DOMAIN} = 1;
	$ads->{NEW_FOREST} = 0;

	print "User Name []:";
	$user_name = <STDIN>;
	chomp $user_name;
	$ads->{USER}{NAME} = $user_name;

	print "User Domain []:";
	$user_domain = <STDIN>;
	chomp $user_domain;
	$ads->{USER}{DOMAIN} = $user_domain;

	print "User Password []:";
	$user_password = <STDIN>;
	chomp $user_password;
	$ads->{USER}{PASSWORD} = $user_password;

	print "full dns name of the top domain []:";	
	$top_dns = <STDIN>;
	chomp $top_dns;
	$ads->{TOP_DNS_NAME} = $top_dns;

	print "suffix of the new domain []:";
	$domain_dns = <STDIN>;
	chomp $domain_dns;
	$ads->{FULL_DNS_NAME} = $domain_dns.".".$top_dns;

	print "netbios name of the new domain []:";
	$domain_netbios = <STDIN>;
	chomp $domain_netbios;
	$ads->{NETBIOS} = $domain_netbios;

	print "folder for database files []:";
	$db_folder = <STDIN>;
	chomp $db_folder;
	$ads->{DB_FOLDER} = $db_folder;

	print "folder for database logs []:";
	$db_logs = <STDIN>;
	chomp $db_logs;
	$ads->{DB_LOGS} = $db_logs;

	print "folder for SYSVOL []:";
	$sysvol_folder = <STDIN>;
	chomp $sysvol_folder;
	$ads->{SYSVOL_FOLDER} = $sysvol_folder;

	#
	# test DNS here
	#

	#
	# test mixed/native here
	#

	print "Administrator password []:";
	$admin_password1 = <STDIN>;
	chomp $admin_password1;
	print "retype Administrator password []:";
	$admin_password2 = <STDIN>;
	chomp $admin_password2;
	if ($admin_password1 eq $admin_password2) {
		$ads->{ADMIN_PASSWORD} = $admin_password1;
	} else {
		$ads->{ADMIN_PASSWORD} = "";
	}

	create_ads_tree($ads);
}

sub do_sub_structure_in_global_structure($) {
	print "go on with do_sub_structure_in_global_structure\n";
}

sub do_new_domain($) {
	my $ads = shift;
	my $ctx;
	
	$ctx->[0]{TEXT}		= "new domain in entire structure";
	$ctx->[0]{ACTION}	= \&do_new_domain_in_entire_structure;

	$ctx->[1]{TEXT}		= "sub domain in existing structure";
	$ctx->[1]{ACTION}	= \&do_sub_domain_in_existing_structure;

	$ctx->[2]{TEXT}		= "sub structure in global structure";
	$ctx->[2]{ACTION}	= \&do_sub_structure_in_global_structure;

	ask_option($ads ,$ctx);
}

sub do_existing_domain($) {
	print "go on with do existing domain\n";
}

sub ask_new_or_exist_domain($) {
	my $ads = shift;
	my $ctx;
	
	$ctx->[0]{TEXT}		= "new domain";
	$ctx->[0]{ACTION}	= \&do_new_domain;

	$ctx->[1]{TEXT}		= "existing domain";
	$ctx->[1]{ACTION}	= \&do_existing_domain;

	ask_option($ads, $ctx);
}

sub main {
	my $ads;

	$ads->{ADS_TREE} = 1;

	ask_new_or_exist_domain($ads);
}

main();
