#!/bin/sh

# Backup persistent CTDB TDBs into the given directory.

# Copyright: DataDirect Networks, 2024
# Authors: Vinit Agnihotri <vagnihotri@ddn.com>
#          Martin Schwenke <mschwenke@ddn.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Options:
#
# -l: Only do the backup if this node is the leader node, otherwise
#     exit with 0.
#
# -L <rc>: Only do the backup if this node is the leader node, otherwise
#     exit with <rc>.

#
# Option/argument handling
#

die()
{
	echo "ERROR: $1"
	exit 1
}

usage()
{
	die "usage: $0 [-l | -L <rc> ] <dir>"
}

leader_only=false
leader_only_rc=0
dir=""

while getopts "L:lh?" opt; do
	case "$opt" in
	L)
		leader_only=true
		leader_only_rc="$OPTARG"
		;;
	l)
		leader_only=true
		;;
	\? | h)
		usage
		;;
	esac
done
shift $((OPTIND - 1))

if [ $# -ne 1 ]; then
	usage
fi

dir="$1"

if [ ! -d "$dir" ]; then
	die "No such directory ${dir}"
fi

if $leader_only; then
	this_node=$(ctdb pnn)
	leader_node=$(ctdb leader)
	if [ "$this_node" != "$leader_node" ]; then
		exit "$leader_only_rc"
	fi
fi

#
# Backups TDBs in timestamped subdirectory
#

dt=$(date "+%Y%m%d%H%M%S")
prefix="ctdb-persistent-db-backup-${dt}"
outdir="${dir}/${prefix}"

# Clean up temporary directory on failure"
trap 'rm -rf ${outdir}' 0

mkdir -p "$outdir"

if ! db_map=$(ctdb getdbmap -X); then
	die "Failed to list databases"
fi
db_list=$(echo "$db_map" | awk -F '|' '$5 == "1" { print $3 }')

cd "$outdir" || die "Failed to change directory to ${dir}"

for db in $db_list; do
	if ! ctdb backupdb "$db" "${db}.backup"; then
		die "Failed to backup ${db}"
	fi
done

#
# Create tarball
#

cd "$dir" || die "Failed to change directory to ${dir}"

tarball="${prefix}.tgz"

if ! tar -c -z -f "$tarball" "$prefix"; then
	die "Failed to create tarball"
fi

echo "Created backup tarball ${dir}/${tarball}"

exit 0
