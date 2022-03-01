#!/bin/bash
#
# Usage copy import-lorikeet.sh and rebase-lorikeet.sh
# into an empty directory maybe call it update-heimdal
# and don't use it for any other work than importing lorikeet heimdal
# into samba.
#
# You need to pass the name of the lorikeet branch
# within the heimdal/ repository as first argument.
#
# You can pass skip_fetch=yes, skip_create=yes, skip_build=yes, skip_test=yes
# as env vars
#

DATE=`date --utc +%Y%m%d%H%M`

lorikeet_branch="$1"
tmp_samba_branch="import-lorikeet-tmp"
new_samba_branch="import-${lorikeet_branch}"
samba_master_branch="$2"
test -n "$samba_master_branch" || {
    samba_master_branch="origin/master"
}

export CC="ccache gcc"

bailout() {
	exit $1;
}

# 1. check if the heimdal repository created with rebase-lorikeet.sh already
# exist
heimdal_check() {
	test -d heimdal || {
		ls heimdal/
		bailout 255
	}

	test -n "$lorikeet_branch" || {
		echo "usage: $0 <lorikeet-branch> [<samba-branch>]"
		bailout 1
	}

	return 0;
}

# 2. initialize the samba repository in the samba subdir
samba_init() {
	test -d samba || {
		mkdir samba || bailout $?
		pushd samba
		git init || bailout $?
		git remote add origin https://git.samba.org/samba.git
		git remote add local-heimdal ../heimdal
		popd
	}

	return 0;
}

# 3. bring the repository uptodate
samba_fetch() {
	test x"$skip_fetch" = x"yes" || {
		pushd samba
		git fetch origin || bailout $?
		git fetch local-heimdal || bailout $?
		popd
	}

	return 0;
}

#
# It would be good if you have a lex:yacc combination which can rebuild this
# files...
#

build_samba() {
	test x"$skip_build" = x"yes" || {
		./configure.developer || return $?
		make -j || return $?
		test x"$skip_test" = x"yes" || {
			TDB_NO_FSYNC=1 make -j test || return $?
		}
	}

	return 0;
}

samba_create() {
	test x"$skip_create" = x"yes" || {
		pushd samba
		lorikeet_commit=`git log -1 local-heimdal/$lorikeet_branch | head -1 | cut -d ' ' -f2`
		echo "local-heimdal/$lorikeet_branch => commit:$lorikeet_commit"
		echo "git update-ref"
		git update-ref refs/heads/$tmp_samba_branch $samba_master_branch || bailout $?
		echo "git checkout"
		git checkout $tmp_samba_branch || bailout $?
		echo "git reset --hard HEAD"
		git reset --hard HEAD
		echo "git clean -d -x -f"
		git clean -d -x -f
		echo "git read-tree..."
		git read-tree -u --prefix=third_party/heimdal-new/ local-heimdal/$lorikeet_branch || bailout $?
		echo "git reset --mixed HEAD"
		git reset --mixed HEAD
		echo "swap old -> new"
		mv third_party/heimdal third_party/heimdal-old || bailout $?
		rsync -a third_party/heimdal-new/ third_party/heimdal || bailout $?
	#	echo "PS1=\"'import-heimdal shell'>\"" > ../.bashrc.samba_create
	#	bash --rcfile ../.bashrc.samba_create
	#	bailout 255
		echo "add changed files to the index"
		git add -u third_party/heimdal
		echo "commit the changed files blindly"
		git commit --no-verify -m "third_party/heimdal: import $lorikeet_branch (commit $lorikeet_commit)"
		echo "cleanup third_party/heimdal"
		rm -rf third_party/heimdal
		git checkout third_party/heimdal
		echo "try to build samba"
		build_samba || {
			echo ""
			echo "Now build the tree and make it compile."
			echo "Missing files can be copied from third_party/heimdal-new/"
			echo "Also run make test!"
		}
		echo ""
		echo "Then do a 'git add third_party/heimdal' and a 'git commit --amend'"
		echo "and write a useful commit message..."
		echo "Then commit all needed changes outside of third_party/heimdal"
		echo "maybe splitted into multiple commits."
		echo ""
		echo "!!!!!!!!!"
		echo ""
		echo "if you this shell exit with 0, then $new_samba_branch will be created"
		echo ""
		echo "PS1=\"'import-heimdal shell'>\"" > ../.bashrc.samba_create
		bash --rcfile ../.bashrc.samba_create || bailout $?
		git branch $new_samba_branch $tmp_samba_branch || bailout $?
		echo "branch $new_samba_branch created"
		popd
	}

	return 0;
}

heimdal_check
samba_init

samba_fetch
samba_create
