# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

define_test ()
{
    _f=$(basename "$0" ".sh")

    printf "%-28s - %s\n" "$_f" "$1"
}
shellcheck_test ()
{
	ok_null
	if type shellcheck >/dev/null 2>&1 ; then
		# Skip some recent checks:
		#
		# SC1090: Can't follow non-constant source. Use a
		#         directive to specify location.
		# SC1091: Not following: FILE was not specified as
		#         input (see shellcheck -x).
		#         - Shellcheck doesn't handle our includes
		#           very well.  Adding directives to handle
		#           include for both in-tree and installed
		#           cases just isn't going to be possible.
		# SC2162: read without -r will mangle backslashes.
		#         - We never read things with backslashes,
		#           unnecessary churn.
		_excludes="SC1090,SC1091,SC2162"
		unit_test shellcheck --exclude="$_excludes" "$@"
	else
		ctdb_test_skip "shellcheck not installed"
	fi
}
