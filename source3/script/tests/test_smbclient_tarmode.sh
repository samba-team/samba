#!/bin/sh

# this runs a simple tarmode test

if [ $# -lt 7 ]; then
cat <<EOF
Usage: test_smbclient_tarmode.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT [create|extract] <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
LOCAL_PATH="$5"
PREFIX="$6"
SMBCLIENT="$7"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 7
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

FAILCOUNT=0

# Check command is available
have_command() {
	type "$1" > /dev/null 2>&1
	return $?
}

# Create a test corpus
create_test_data() {

	local DIR="$1"
	local BS=1024
	local NUM_FILES=10
	local NORND_COUNT=25

	# Bomb if dir exists
	if [ -e "$DIR" ]; then
		echo "Test data directory '$DIR' already exists!"
		false
		return
	fi

	if ! mkdir -p "$DIR" > /dev/null 2>&1; then
		echo "Couldn't create test data directory '$DIR'"
		false
		return
	fi

	local I=1
	if have_command "od"; then # Use random file sizes
		local RND_COUNT
		for RND_COUNT in `od -An -N$NUM_FILES -tu1 < /dev/urandom`; do
			if ! dd if=/dev/urandom of="$DIR/file.$I" bs=$BS count=$RND_COUNT > /dev/null 2>&1; then
				echo "Couldn't create test file '$DIR/file.$I' (random size)"
				false
				return
			fi
			I=`expr $I + 1`
		done
	else # Fallback to same file sizes
		while [ $I -le $NUM_FILES ]; do
			if ! dd if=/dev/urandom of="$DIR/file.$I" bs=$BS count=$NORND_COUNT > /dev/null 2>&1; then
				echo "Couldn't create test file '$DIR/file.$I' (static size)"
				false
				return
			fi
			I=`expr $I + 1`
		done
	fi

	true
	return

}

# Check that two directories are equivalent (In Data content)
validate_data() {
	local DIR1="$1"
	local DIR2="$2"

	diff -r "$DIR1" "$DIR2"
	return $?
}

# Test tarmode -Tc
test_tarmode_creation() {

	# Clear temp data
	rm -rf -- "$PREFIX"/tarmode > /dev/null 2>&1
	rm -f "$PREFIX"/tarmode.tar > /dev/null 2>&1
	rm -rf "$LOCAL_PATH"/tarmode > /dev/null 2>&1

	# Build the test data
	if ! create_test_data "$LOCAL_PATH/tarmode"; then
		echo "Test data creation failed"
		false
		return
	fi

	# Create tarfile with smbclient
	if ! $SMBCLIENT //$SERVER/tmp $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 \
			$ADDARGS -c "tarmode full" -Tc "$PREFIX/tarmode.tar" "/tarmode"; then
		echo "Couldn't create tar file with tarmode -Tc"
		false
		return
	fi

	# Extract data to verify
	if ! tar -xf "$PREFIX/tarmode.tar" -C "$PREFIX"; then
		echo "Couldn't extract data from created tarfile"
		false
		return
	fi

	# Verify data
	if ! validate_data "$PREFIX/tarmode" "$LOCAL_PATH/tarmode"; then
		echo "Data not equivalent"
		false
		return
	fi

	true
	return

}

# Test tarmode -Tx
test_tarmode_extraction() {

	# Clear temp data
	rm -rf -- "$PREFIX"/tarmode > /dev/null 2>&1
	rm -f "$PREFIX"/tarmode.tar > /dev/null 2>&1
	rm -rf "$LOCAL_PATH"/tarmode > /dev/null 2>&1

	# Build the test data
	if ! create_test_data "$PREFIX/tarmode"; then
		echo "Test data creation failed"
		false
		return
	fi

	# Create tarfile to extract on client
	if ! tar -cf "$PREFIX/tarmode.tar" -C "$PREFIX" tarmode; then
		echo "Couldn't create tar archive"
		false
		return
	fi

	# Extract tarfile with smbclient
	if ! $SMBCLIENT //$SERVER/tmp $CONFIGURATION -U$USERNAME%$PASSWORD -I $SERVER_IP -p 139 \
			$ADDARGS -c "tarmode full" -Tx "$PREFIX/tarmode.tar"; then
		echo "Couldn't extact tar file with tarmode -Tx"
		false
		return
	fi

	# Verify data
	if ! validate_data "$PREFIX/tarmode" "$LOCAL_PATH/tarmode"; then
		echo "Data not equivalent"
		false
		return
	fi

	true
	return

}

testit "test_tarmode_creation" \
	test_tarmode_creation || FAILCOUNT=`expr $FAILCOUNT + 1`

testit "test_tarmode_extraction" \
	test_tarmode_extraction || FAILCOUNT=`expr $FAILCOUNT + 1`

testok $0 $FAILCOUNT
