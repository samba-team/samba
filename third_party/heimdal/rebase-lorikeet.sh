#!/bin/bash
#
# Usage copy import-lorikeet.sh and rebase-lorikeet.sh
# into an empty directory maybe call it update-heimdal
# and don't use it for any other work than importing lorikeet heimdal
# into samba.
#
# These parameter might be changed:
#
# heimdal_my_wip_name
# heimdal_my_wip_url
# old_lorikeet_branch
#
# you can pass skip_fetch=yes and/or skip_rebase=yes as env vars
#

# this needs to be reachable from
old_lorikeet_branch=$1

DATE=`date --utc +%Y%m%d%H%M`

heimdal_my_wip_name="heimdal-local"
heimdal_my_wip_url="/data/heimdal"

if test x"$old_lorikeet_branch" = x""; then
	old_lorikeet_branch="heimdal-metze-wip/lorikeet-heimdal"
fi

tmp_lorikeet_branch="lorikeet-heimdal-tmp"
new_lorikeet_branch="lorikeet-heimdal-${DATE}"

bailout() {
	exit $1;
}

# 1. create a local heimdal repository in the heimdal subdir

heimdal_init() {
	test -d heimdal || {
		mkdir heimdal || bailout $?
		pushd heimdal
		git init || bailout $?
		git remote add heimdal-git https://github.com/heimdal/heimdal.git
		git remote add lorikeet-heimdal-abartlet ssh://git.samba.org/data/git/abartlet/lorikeet-heimdal.git/.git
		git remote add lorikeet-heimdal https://gitlab.com/samba-team/devel/lorikeet-heimdal
		git remote add ${heimdal_my_wip_name} ${heimdal_my_wip_url}
		popd
	}

	return 0;
}

# 2. bring the repository uptodate
heimdal_fetch() {
	test x"$skip_fetch" = x"yes" || {
		pushd heimdal
		git fetch heimdal-git || bailout $?
		git fetch lorikeet-heimdal-abartlet || bailout $?
		git fetch ${heimdal_my_wip_name} || bailout $?
		popd
	}

	return 0;
}

# 3. rebase the old_lorikeet_branch on top of heimdals trunk
heimdal_rebase() {
	test x"$skip_rebase" = x"yes" || {
		pushd heimdal
		echo "git update-ref"
		git update-ref refs/heads/$tmp_lorikeet_branch $old_lorikeet_branch || bailout $?
		echo "git checkout"
		git checkout $tmp_lorikeet_branch || bailout $?
		echo "git reset --hard HEAD"
		git reset --hard HEAD
		echo "git rebase"
		git rebase heimdal-git/master || {
			echo "PS1=\"'git-rebase shell'>\"" > ../.bashrc.heimdal_rebase
			bash --rcfile ../.bashrc.heimdal_rebase || {
				ret=$?
				echo "git rebase --abort (just in case)"
				git rebase --abort
				bailout $ret
			}
		}
		echo "git rebase --abort (just in case)"
		git rebase --abort
		echo "Now build and test the lorikeet heimdal tree"
		echo "and exit with 0 if you want to create a $new_lorikeet_branch branch"
		echo ""
		echo "PS1=\"'build shell'>\"" > ../.bashrc.heimdal_build
		bash --rcfile ../.bashrc.heimdal_build || bailout $?
		git branch $new_lorikeet_branch $tmp_lorikeet_branch || bailout $?
		echo "branch $new_lorikeet_branch created"
		popd
	}

	return 0;
}

heimdal_init
heimdal_fetch
heimdal_rebase
