all:
	cd libtelnet; make CC="${CC}"
	cd telnet; make CC="${CC}"
	cd telnetd; make CC="${CC}"

.DEFAULT:
	cd libtelnet; make $@ WHAT=${WHAT} CC="${CC}"
	cd telnet; make $@ WHAT=${WHAT} CC="${CC}"
	cd telnetd; make $@ WHAT=${WHAT} CC="${CC}"
