#######################
# Start LIBRARY swig_tdb
[LIBRARY::swig_tdb]
REQUIRED_SUBSYSTEMS = LIBTDB
# End LIBRARY swig_tdb
#######################

#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::swig_dcerpc]
REQUIRED_SUBSYSTEMS = LIBCLI NDR_MISC LIBBASIC CONFIG RPC_NDR_SAMR RPC_NDR_LSA
# End LIBRARY swig_dcerpc
#######################
