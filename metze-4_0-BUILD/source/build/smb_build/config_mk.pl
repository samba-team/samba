###########################################################
### SMB Build System					###
### - config.mk parsing functions			###
###							###
###  Copyright (C) Stefan (metze) Metzmacher 2004	###
###  Released under the GNU GPL				###
###########################################################

###########################################################
# The parsing function which parses the file
#
# $result = _parse_config_mk($filename)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $result -	the resulting structure
#
# $result->{ERROR_CODE} -	the error_code, '0' means success
# $result->{ERROR_STR} -	the error string
#
# $result->{$key}{KEY} -	the key == the variable which was parsed
# $result->{$key}{VAL} -	the value of the variable
sub _parse_config_mk($)
{
	my $filename = shift;
	my $result;
	my $linenum = -1;
	my $waiting = 0;
	my $key;	

	$result->{ERROR_CODE} = -1;

	open(CONFIG_MK, "< $filename") || die ("Can't open $filename\n");

	while (<CONFIG_MK>) {
		my $line = $_;
		my $val;

		$linenum++;

		#
		# lines beginnig with '#' are ignored
		# 
		if ($line =~ /^\#.*$/) {
			next;
		}

		#
		# 1.)	lines with an aplhanumeric character indicate
		# 	a new variable, 
		# 2.)	followed by zero or more whitespaces or tabs
		# 3.)	then one '=' character
		# 4.)	followed by the value of the variable
		# 5.)	a newline ('\n') can be escaped by a '\' before the newline
		#	and the next line needs to start with a tab ('\t')
		#
		if ($line =~ /^([a-zA-Z0-9_]+)[\t ]*=(.*)$/) {
			$key = $1;
			$val = $2;

			#
			# when we have a '\' before the newline 
			# then skip it and wait for the next line.
			#
			if ($val =~ /(.*)(\\)$/) {
				$val = $1;
				$waiting = 1;		
			} else {
				$waiting = 0;
			}

			#
			# trim whitespaces and tabs to just one whiespace
			#
			$val =~ s/([\t ]+)/ /g;

			$result->{$key}{KEY} = $key;
			$result->{$key}{VAL} = $val;
			next;
		}

		#
		# when we are waiting for a value to continue then
		# check if it has a leading tab.
		#
		if (($waiting == 1) && ($line =~ /^\t(.*)$/)) {
			$val = $1;

			#
			# when we have a '\' before the newline 
			# then skip it and wait for the next line.
			#
			if ($val =~ /(.*)( \\)$/) {
				$val = $1;
				$waiting = 1;		
			} else {
				$waiting = 0;
			}

			#
			# trim whitespaces and tabs to just one whiespace
			#
			$val =~ s/([\t ]+)/ /g;

			$result->{$key}{VAL} .= " ";
			$result->{$key}{VAL} .= $val;
			next;
		}

		#
		# catch empty lines they're ignored
		# and we're no longer waiting for the value to continue
		#
		if ($line =~ /^$/) {
			$waiting = 0;
			next;
		}

		close(CONFIG_MK);

		$result->{ERROR_STR} = "Bad line while parsing $filename\n$filename:$linenum: $line";

		return $result;
	}

	close(CONFIG_MK);

	$result->{ERROR_CODE} = 0;

	return $result;
}

###########################################################
# A caching function to avoid to parse
# a file twice or more
#
# $result = _get_parse_results($filename)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $result -	the resulting structure
#
# $result->{ERROR_CODE} -	the error_code, '0' means success
# $result->{ERROR_STR} -	the error string
#
# $result->{$key}{KEY} -	the key == the variable which was parsed
# $result->{$key}{VAL} -	the value of the variable
my $_get_parse_results_cache;
sub _get_parse_results($)
{
	my $filename = shift;

	if ((!defined($_get_parse_results_cache->{$filename}{ERROR_CODE}))
		||($_get_parse_results_cache->{$filename}{ERROR_CODE} != 0)) {
		$_get_parse_results_cache->{$filename} = _parse_config_mk($filename);
	}

	return $_get_parse_results_cache->{$filename};
}

###########################################################
# The fetching function to fetch the value of a variable 
# out of the file
#
# $value = _fetch_key_from_config_mk($filename,$variable)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $variable -	the variable name of which we want the value
#
# $value -	the value of the variable
sub _fetch_key_from_config_mk($$)
{
	my $filename = shift;
	my $key = shift;
	my $val = "";
	my $result;

	$result = _get_parse_results($filename);

	if ($result->{ERROR_CODE} != 0) {
		die ($result->{ERROR_STR});
	}

	if (defined($result->{$key})) {
		$val = $result->{$key}{VAL};
	}

	return $val;
}

###########################################################
# A function for fetching MODULE_<module>_<parameter>
# variables out of a config.mk file
#
# $value = module_get($filename,$module,$parameter)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $module -	the middle part of the variable name of which we want the value
#
# $parameter -	the last part of the variable name of which we want the value
#
# $value -	the value of the variable
sub module_get($$$)
{
	my $filename = shift;
	my $module = shift;
	my $_var = shift;

	my $var = "MODULE_".$module."_".$_var;

	return _fetch_key_from_config_mk($filename,$var);
}

###########################################################
# A function for fetching SUBSYSTEM_<subsystem>_<parameter>
# variables out of a config.mk file
#
# $value = module_get($filename,$subsystem,$parameter)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $subsystem -	the middle part of the variable name of which we want the value
#
# $parameter -	the last part of the variable name of which we want the value
#
# $value -	the value of the variable
sub subsystem_get($$$)
{
	my $filename = shift;
	my $subsystem = shift;
	my $_var = shift;

	my $var = "SUBSYSTEM_".$subsystem."_".$_var;

	return _fetch_key_from_config_mk($filename,$var);
}

###########################################################
# A function for fetching LIBRARY_<library>_<parameter>
# variables out of a config.mk file
#
# $value = module_get($filename,$library,$parameter)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $library -	the middle part of the variable name of which we want the value
#
# $parameter -	the last part of the variable name of which we want the value
#
# $value -	the value of the variable
sub library_get($$$)
{
	my $filename = shift;
	my $library = shift;
	my $_var = shift;

	my $var = "LIBRARY_".$library."_".$_var;

	return _fetch_key_from_config_mk($filename,$var);
}

###########################################################
# A function for fetching BINARY_<binary>_<parameter>
# variables out of a config.mk file
#
# $value = module_get($filename,$binary,$parameter)
#
# $filename -	the path of the config.mk file
#		which should be parsed
#
# $binary -	the middle part of the variable name of which we want the value
#
# $parameter -	the last part of the variable name of which we want the value
#
# $value -	the value of the variable
sub binary_get($$$)
{
	my $filename = shift;
	my $binary = shift;
	my $_var = shift;

	my $var = "BINARY_".$binary."_".$_var;

	return _fetch_key_from_config_mk($filename,$var);
}
