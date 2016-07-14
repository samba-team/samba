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
	if type shellcheck >/dev/null ; then
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
		# SC2164: Use cd ... || exit in case cd fails.
		#         - Most hits are on known directories.  Too
		#           much churn, maybe later.
		# SC2166: Prefer [ p ] && [ q ] as [ p -a q ] is not
		#         well defined.
		# SC2166: Prefer [ p ] || [ q ] as [ p -o q ] is not
		#         well defined.
		#         - This can cause issues but the number of
		#           true positives will be very low.  Too much
		#           churn, maybe later.
		_excludes="SC1090,SC1091,SC2162,SC2164,SC2166"
		unit_test shellcheck --exclude="$_excludes" "$@"
	else
		echo "WARNING: shellcheck not installed, skipping test"
		unit_test true
	fi
}
