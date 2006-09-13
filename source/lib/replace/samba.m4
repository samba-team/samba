m4_include(lib/replace/libreplace.m4)

SMB_EXT_LIB(LIBREPLACE_EXT, [${LIBDL}])
SMB_ENABLE(LIBREPLACE_EXT)

LIBREPLACE_DIR=`echo ${libreplacedir} |sed -e 's/^\.\///g'`

LIBREPLACE_OBJS=""
for obj in ${LIBREPLACEOBJ}; do
	LIBREPLACE_OBJS="${LIBREPLACE_OBJS} ${LIBREPLACE_DIR}/${obj}"
done

SMB_SUBSYSTEM(LIBREPLACE,
	[${LIBREPLACE_OBJS}],
	[LIBREPLACE_EXT],
	[-Ilib/replace])

LIBREPLACE_HOSTCC_OBJS=`echo ${LIBREPLACE_OBJS} |sed -e 's/\.o/\.ho/g'`

SMB_SUBSYSTEM(LIBREPLACE_HOSTCC,
	[${LIBREPLACE_HOSTCC_OBJS}],
	[],
	[-Ilib/replace])
