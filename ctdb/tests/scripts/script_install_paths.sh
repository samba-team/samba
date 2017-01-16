# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# $ctdb_dir is set in common.sh
if [  -n "$ctdb_dir" ] ; then
	# Running in-tree
	CTDB_SCRIPTS_BASE="${ctdb_dir}/config"
	CTDB_SCRIPTS_INIT_SCRIPT="${ctdb_dir}/config/ctdb.init"
	CTDB_SCRIPTS_SBIN_DIR="${ctdb_dir}/config"
	CTDB_SCRIPTS_TOOLS_BIN_DIR="${ctdb_dir}/tools"
	CTDB_SCRIPTS_TOOLS_HELPER_DIR="${ctdb_dir}/tools"
else
	# Installed
	CTDB_SCRIPTS_BASE="/usr/local/etc/ctdb"
	CTDB_SCRIPTS_INIT_SCRIPT="" # No ideas here... this is a packaging choice
	CTDB_SCRIPTS_SBIN_DIR="/usr/local/sbin"
	CTDB_SCRIPTS_TOOLS_BIN_DIR="/usr/local/bin"
	CTDB_SCRIPTS_TOOLS_HELPER_DIR="/usr/local/libexec/ctdb"
fi

export CTDB_SCRIPTS_BASE CTDB_SCRIPTS_BIN_DIR CTDB_SCRIPTS_INIT_SCRIPT \
	CTDB_SCRIPTS_SBIN_DIR CTDB_SCRIPTS_TOOLS_HELPER_DIR
