#
#	.bashrc -- Login shell startup script for windows using Mbedthis winTools
#
#	Copyright (c) Mbedthis Software, 2003-2005. All Rights Reserved.
#

TERM=ansi
#
#	Set the desired .NET Framework
#
# FRAMEWORK=v1.0.3705
FRAMEWORK=v1.1.4322
# FRAMEWORK=v2.0.40607

#
#	Set the desired Microsoft C Compiler version
#
# PREFERRED_CC=VS2005
# PREFERRED_CC=VS2003
# PREFERRED_CC=VS.NET
PREFERRED_CC=VS6

#
#	Set to 1 if VXWORKS support is required
#
#	VXWORKS=1

HOME=`pwd`
if [ ! -x winTools -o ! -x winTools/cygpath.exe ]
then
	echo "Can't find build tools. Install build tools in $HOME/winTools"
fi

ROOT=`winTools/cygpath -u $HOMEDRIVE` 
: ${ROOT:=C:/}
APPWEB_PATH="${HOME}/bin/DEBUG:${HOME}/bin/RELEASE:${HOME}/bin:${HOME}/winTools"
CDPATH=".:${HOME}:${HOME}/http:${HOME}/http/modules:${HOME}/packages"
PS1="$ "

export CDPATH INCLUDE LIB LIBPATH PATH PS1 TERM

echo -e "\n\n###################################################"
echo "Mbedthis AppWeb, Cygwin build tools."
echo "Using compiler: $PREFERRED_CC, .NET framework: $FRAMEWORK"
echo -e "###################################################"

################################################################################

#
#	Setup for Visual Studio and SDK
#
if [ $PREFERRED_CC == "VS2005" ]
then
	#
	#	Visual Studio .NET 2005 defines. 
	#
	CYNET="${ROOT}/Program Files/Microsoft Visual Studio 8"
	DOSNET="C:/Program Files/Microsoft Visual Studio 8"
	PATH="$APPWEB_PATH:$CYNET/Common7/IDE:$CYNET/VC/BIN:$CYNET/VC/VCPackages:$CYNET/Common7/Tools:$CYNET/Common7/Tools/bin:$CYNET/SDK/v2.0/bin:`cygpath -W`/Microsoft.NET/Framework/v2.0.40607:$CYNET/SDK/v2.0/bin:$PATH"
	INCLUDE="$DOSNET/VC/ATLMFC/INCLUDE;$DOSNET/VC/INCLUDE;$DOSNET/VC/PlatformSDK/include;$DOSNET/SDK/v2.0/include;$INCLUDE"
	LIB="$DOSNET/VC/ATLMFC/LIB;$DOSNET/VC/LIB;$DOSNET/VC/PlatformSDK/lib;$DOSNET/SDK/v2.0/lib;$LIB"
	LIBPATH=c:/WINDOWS/Microsoft.NET/Framework/$FRAMEWORK
fi

if [ $PREFERRED_CC == "VS2003" ]
then
	#
	#	Visual Studio .NET 2003 defines. 
	#
	CYNET="${ROOT}/Program Files/Microsoft Visual Studio .NET 2003"
	DOSNET="C:/Program Files/Microsoft Visual Studio .NET 2003"
	PATH="$APPWEB_PATH:$CYNET/Common7/IDE:$CYNET/VC7/BIN:$CYNET/Common7/Tools:$CYNET/Common7/Tools/bin/prerelease:$CYNET/Common7/Tools/bin:$CYNET/FrameworkSDK/bin:${ROOT}/WINDOWS/Microsoft.NET/Framework/$FRAMEWORK:$CYNET/SDK/v1.1/bin:$PATH"
	INCLUDE="$DOSNET/VC7/ATLMFC/INCLUDE;$DOSNET/VC7/INCLUDE;$DOSNET/VC7/PlatformSDK/include/prerelease;$DOSNET/VC7/PlatformSDK/include;$DOSNET/FrameworkSDK/include;$INCLUDE"
	LIB="$DOSNET/VC7/ATLMFC/LIB;$DOSNET/VC7/LIB;$DOSNET/VC7/PlatformSDK/lib/prerelease;$DOSNET/VC7/PlatformSDK/lib;$DOSNET/FrameworkSDK/lib;$LIB"
fi


if [ $PREFERRED_CC == "VS.NET" ]
then
	#
	#	Visual Studio .NET defines. 
	#
	CYNET="${ROOT}/Program Files/Microsoft Visual Studio .NET"
	DOSNET="C:/Program Files/Microsoft Visual Studio .NET"
	PATH="$APPWEB_PATH:$CYNET/Common7/IDE:$CYNET/VC7/BIN:$CYNET/Common7/Tools:$CYNET/Common7/Tools/bin/prerelease:$CYNET/Common7/Tools/bin:$CYNET/FrameworkSDK/bin:${ROOT}/WINDOWS/Microsoft.NET/Framework/$FRAMEWORK:$CYNET/SDK/v1.0/bin:$PATH"
	INCLUDE="$DOSNET/VC7/ATLMFC/INCLUDE;$DOSNET/VC7/INCLUDE;$DOSNET/VC7/PlatformSDK/include/prerelease;$DOSNET/VC7/PlatformSDK/include;$DOSNET/FrameworkSDK/include;$INCLUDE"
	LIB="$DOSNET/VC7/ATLMFC/LIB;$DOSNET/VC7/LIB;$DOSNET/VC7/PlatformSDK/lib/prerelease;$DOSNET/VC7/PlatformSDK/lib;$DOSNET/FrameworkSDK/lib;$LIB"
fi


if [ $PREFERRED_CC == "VS6" ]
then
	#	Visual Studio 6 defines. 
	#
	CYNET="${ROOT}/Program Files/Microsoft Visual Studio"
	DOSNET="C:/Program Files/Microsoft Visual Studio"
	PATH="$APPWEB_PATH:$CYNET/Common/MSDev98/bin:$CYNET/VC98/BIN:$CYNET/Common/IDE:$CYNET/Common/Tools/WinNT:$CYNET/Common/Tools:$PATH"
	INCLUDE="$DOSNET/VC98/ATLMFC/INCLUDE;$DOSNET/VC98/INCLUDE;$DOSNET/VC98/MFC/INCLUDE;$INCLUDE"
	LIB="$DOSNET/VC98/LIB;$DOSNET/VC98/MFC/LIB;$LIB"
fi

if [ $VXWORKS ]
then
	#
	#	Required by VxWorks
	#
	WIND_BASE=C:/tornado
	WIND_HOST_TYPE=x86-win32
	WIND_REGISTRY=coalsack
	WIND_LMHOST=coalsack
	BLD_VX_HOST=i386-wrs-vxworks
	VX_TOOLS=`cygpath $WIND_BASE`/host/$WIND_HOST_TYPE
	export WIND_BASE WIND_HOST_TYPE WIND_REGISTRY WIND_LMHOST BLD_VX_HOST

	#
	#	Use cygwin make and tools by preference
	#
	PATH="$APPWEB_PATH:$VX_TOOLS/bin:$PATH"
fi

#
#	Make required directories for CYGWIN
#
if [ ! -x /bin/bash.exe ]
then
	DIR=`cygpath -w "$HOME/winTools"`
 	echo -e "\nCreating /bin"
	echo Mounting \"${DIR}\" as /bin
	mount -f -b "$DIR" /bin
fi

if [ ! -x /tmp ]
then
 	mkdir -p tmp
	DIR=`cygpath -w "$HOME/tmp"`
 	echo -e "\nCreating /tmp"
	echo Mounting \"${DIR}\" as /tmp
 	mount -f -b "$DIR" /tmp
fi
echo

################################################################################
#
#	Do a bit of validation 
#
type cl 2>/dev/null >/dev/null
if [ $? -ne 0 ]
then
	echo "Can't find compiler: cl. Check WIN/bashrc settings for PATH"
fi
set -o vi

################################################################################
