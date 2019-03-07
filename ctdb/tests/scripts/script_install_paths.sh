# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

if ! $CTDB_TESTS_ARE_INSTALLED ; then
	if [ ! -f "${CTDB_TEST_DIR}/run_tests.sh" ] ; then
		die "Tests not installed but can't find run_tests.sh"
	fi

	ctdb_dir=$(dirname "$CTDB_TEST_DIR")

	top_dir=$(cd -P "$ctdb_dir" && echo "$PWD") # real path
	if [ ! -d "${top_dir}/bin" ] ; then
		top_dir=$(dirname "$top_dir")
	fi

	CTDB_SCRIPTS_BASE="${ctdb_dir}/config"
	CTDB_SCRIPTS_INIT_SCRIPT="${ctdb_dir}/config/ctdb.init"
	CTDB_SCRIPTS_SBIN_DIR="${ctdb_dir}/config"
	CTDB_SCRIPTS_TOOLS_BIN_DIR="${ctdb_dir}/tools"
	CTDB_SCRIPTS_TOOLS_HELPER_DIR="${ctdb_dir}/tools"
	CTDB_SCRIPTS_HELPER_BINDIR="${top_dir}/bin"
	CTDB_SCRIPTS_DATA_DIR="${ctdb_dir}/config"
	CTDB_SCRIPTS_TESTS_BINDIR="${top_dir}/bin"
else
	# Installed
	CTDB_SCRIPTS_BASE="/usr/local/etc/ctdb"
	CTDB_SCRIPTS_INIT_SCRIPT="" # No ideas here... this is a packaging choice
	CTDB_SCRIPTS_SBIN_DIR="/usr/local/sbin"
	CTDB_SCRIPTS_TOOLS_BIN_DIR="/usr/local/bin"
	CTDB_SCRIPTS_TOOLS_HELPER_DIR="/usr/local/libexec/ctdb"
	CTDB_SCRIPTS_HELPER_BINDIR="/usr/local/libexec/ctdb"
	CTDB_SCRIPTS_DATA_DIR="/usr/local/share/ctdb"
	CTDB_SCRIPTS_TESTS_BINDIR="/usr/local/libexec/ctdb/tests"
fi

export CTDB_SCRIPTS_BASE \
       CTDB_SCRIPTS_BIN_DIR \
       CTDB_SCRIPTS_INIT_SCRIPT \
       CTDB_SCRIPTS_SBIN_DIR \
       CTDB_SCRIPTS_TOOLS_BIN_DIR \
       CTDB_SCRIPTS_TOOLS_HELPER_DIR \
       CTDB_SCRIPTS_HELPER_BINDIR \
       CTDB_SCRIPTS_DATA_DIR \
       CTDB_SCRIPTS_TESTS_BINDIR
