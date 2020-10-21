release_dir=$SRCDIR_ABS/source4/selftest/provisions/$RELEASE

ldbadd="ldbadd"
if [ -x "$BINDIR/ldbadd" ]; then
    ldbadd="$BINDIR/ldbadd"
fi

ldbmodify="ldbmodify"
if [ -x "$BINDIR/ldbmodify" ]; then
    ldbmodify="$BINDIR/ldbmodify"
fi

ldbdel="ldbdel"
if [ -x "$BINDIR/ldbdel" ]; then
    ldbdel="$BINDIR/ldbdel"
fi

ldbsearch="ldbsearch"
if [ -x "$BINDIR/ldbsearch" ]; then
    ldbsearch="$BINDIR/ldbsearch"
fi

ldbrename="ldbrename"
if [ -x "$BINDIR/ldbrename" ]; then
    ldbrename="$BINDIR/ldbrename"
fi

samba_tdbrestore="tdbrestore"
if [ -x "$BINDIR/tdbrestore" ]; then
    samba_tdbrestore="$BINDIR/tdbrestore"
fi

samba_undump="$SRCDIR_ABS/source4/selftest/provisions/undump.sh"

undump() {
    $samba_undump $release_dir $PREFIX_ABS/$RELEASE $samba_tdbrestore
}

add_dangling_link() {
    ldif=$release_dir/add-dangling-forwardlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-initially-normal-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/delete-only-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_dangling_backlink() {
    ldif=$release_dir/add-dangling-backlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-dangling-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_deleted_dangling_backlink() {
    ldif=$release_dir/add-deleted-backlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-deleted-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_deleted_target_backlink() {
    ldif=$release_dir/add-deleted-target-backlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-deleted-target-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

revive_links_on_deleted_group() {
    ldif=$release_dir/revive-links-on-deleted-group.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

revive_backlink_on_deleted_group() {
    ldif=$release_dir/revive-backlink-on-deleted-group.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_deleted_target_link() {
    ldif=$release_dir/add-dangling-deleted-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_two_more_users() {
    ldif=$release_dir/add-two-more-users.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_four_more_links() {
    ldif=$release_dir/add-four-more-links.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

remove_one_link() {
    ldif=$release_dir/remove-one-more-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

remove_one_user() {
    ldif=$release_dir/remove-one-more-user.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

move_one_user() {
    TZ=UTC $ldbrename -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb 'cn=user1,cn=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' 'cn=user1x,cn=users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dangling_one_way_dn() {
    ldif=$release_dir/dangling-one-way-dn.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
        return 1
    fi
}

deleted_one_way_dn() {
    ldif=$release_dir/deleted-one-way-dn.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
        return 1
    fi
}

dangling_one_way_link() {
    ldif=$release_dir/dangling-one-way-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/CN%3DCONFIGURATION,DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
        return 1
    fi
}

add_dangling_multi_valued() {
    # multi1 - All 4 backlinks
    # multi2 - Missing all 4 backlinks
    # multi3 - Missing 2 backlinks
    # Administrator - Has 2 too many backlinks
    # multi5 - Has 2 backlinks but no forward links
    ldif=$release_dir/add-dangling-multilink-users.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-initially-normal-multilink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/delete-only-multi-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-dangling-multi-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}
