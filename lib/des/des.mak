# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=des - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to des - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "des - Win32 Release" && "$(CFG)" != "des - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "des.mak" CFG="des - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "des - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "des - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "des - Win32 Debug"
CPP=cl.exe
RSC=rc.exe
MTL=mktyplib.exe

!IF  "$(CFG)" == "des - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\des.dll"

CLEAN : 
	-@erase "$(INTDIR)\cbc3_enc.obj"
	-@erase "$(INTDIR)\cbc_cksm.obj"
	-@erase "$(INTDIR)\cbc_enc.obj"
	-@erase "$(INTDIR)\cfb64ede.obj"
	-@erase "$(INTDIR)\cfb64enc.obj"
	-@erase "$(INTDIR)\cfb_enc.obj"
	-@erase "$(INTDIR)\des_enc.obj"
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\ecb3_enc.obj"
	-@erase "$(INTDIR)\ecb_enc.obj"
	-@erase "$(INTDIR)\ede_enc.obj"
	-@erase "$(INTDIR)\enc_read.obj"
	-@erase "$(INTDIR)\enc_writ.obj"
	-@erase "$(INTDIR)\fcrypt.obj"
	-@erase "$(INTDIR)\key_par.obj"
	-@erase "$(INTDIR)\ncbc_enc.obj"
	-@erase "$(INTDIR)\ofb64ede.obj"
	-@erase "$(INTDIR)\ofb64enc.obj"
	-@erase "$(INTDIR)\ofb_enc.obj"
	-@erase "$(INTDIR)\passwd_dlg.obj"
	-@erase "$(INTDIR)\pcbc_enc.obj"
	-@erase "$(INTDIR)\qud_cksm.obj"
	-@erase "$(INTDIR)\read_pwd.obj"
	-@erase "$(INTDIR)\rnd_keys.obj"
	-@erase "$(INTDIR)\rpc_enc.obj"
	-@erase "$(INTDIR)\set_key.obj"
	-@erase "$(INTDIR)\str2key.obj"
	-@erase "$(INTDIR)\supp.obj"
	-@erase "$(OUTDIR)\des.dll"
	-@erase "$(OUTDIR)\des.exp"
	-@erase "$(OUTDIR)\des.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\roken" /I "." /I "..\..\include" /I "..\..\include\win32" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "HAVE_CONFIG_H" /YX /c
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\roken" /I "." /I "..\..\include" /I\
 "..\..\include\win32" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "HAVE_CONFIG_H"\
 /Fp"$(INTDIR)/des.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/des.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ..\roken\Release\roken.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
LINK32_FLAGS=..\roken\Release\roken.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/des.pdb" /machine:I386 /def:".\des.def"\
 /out:"$(OUTDIR)/des.dll" /implib:"$(OUTDIR)/des.lib" 
DEF_FILE= \
	".\des.def"
LINK32_OBJS= \
	"$(INTDIR)\cbc3_enc.obj" \
	"$(INTDIR)\cbc_cksm.obj" \
	"$(INTDIR)\cbc_enc.obj" \
	"$(INTDIR)\cfb64ede.obj" \
	"$(INTDIR)\cfb64enc.obj" \
	"$(INTDIR)\cfb_enc.obj" \
	"$(INTDIR)\des_enc.obj" \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\ecb3_enc.obj" \
	"$(INTDIR)\ecb_enc.obj" \
	"$(INTDIR)\ede_enc.obj" \
	"$(INTDIR)\enc_read.obj" \
	"$(INTDIR)\enc_writ.obj" \
	"$(INTDIR)\fcrypt.obj" \
	"$(INTDIR)\key_par.obj" \
	"$(INTDIR)\ncbc_enc.obj" \
	"$(INTDIR)\ofb64ede.obj" \
	"$(INTDIR)\ofb64enc.obj" \
	"$(INTDIR)\ofb_enc.obj" \
	"$(INTDIR)\passwd_dlg.obj" \
	"$(INTDIR)\pcbc_enc.obj" \
	"$(INTDIR)\qud_cksm.obj" \
	"$(INTDIR)\read_pwd.obj" \
	"$(INTDIR)\rnd_keys.obj" \
	"$(INTDIR)\rpc_enc.obj" \
	"$(INTDIR)\set_key.obj" \
	"$(INTDIR)\str2key.obj" \
	"$(INTDIR)\supp.obj"

"$(OUTDIR)\des.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "des - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\des.dll"

CLEAN : 
	-@erase "$(INTDIR)\cbc3_enc.obj"
	-@erase "$(INTDIR)\cbc_cksm.obj"
	-@erase "$(INTDIR)\cbc_enc.obj"
	-@erase "$(INTDIR)\cfb64ede.obj"
	-@erase "$(INTDIR)\cfb64enc.obj"
	-@erase "$(INTDIR)\cfb_enc.obj"
	-@erase "$(INTDIR)\des_enc.obj"
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\ecb3_enc.obj"
	-@erase "$(INTDIR)\ecb_enc.obj"
	-@erase "$(INTDIR)\ede_enc.obj"
	-@erase "$(INTDIR)\enc_read.obj"
	-@erase "$(INTDIR)\enc_writ.obj"
	-@erase "$(INTDIR)\fcrypt.obj"
	-@erase "$(INTDIR)\key_par.obj"
	-@erase "$(INTDIR)\ncbc_enc.obj"
	-@erase "$(INTDIR)\ofb64ede.obj"
	-@erase "$(INTDIR)\ofb64enc.obj"
	-@erase "$(INTDIR)\ofb_enc.obj"
	-@erase "$(INTDIR)\passwd_dlg.obj"
	-@erase "$(INTDIR)\pcbc_enc.obj"
	-@erase "$(INTDIR)\qud_cksm.obj"
	-@erase "$(INTDIR)\read_pwd.obj"
	-@erase "$(INTDIR)\rnd_keys.obj"
	-@erase "$(INTDIR)\rpc_enc.obj"
	-@erase "$(INTDIR)\set_key.obj"
	-@erase "$(INTDIR)\str2key.obj"
	-@erase "$(INTDIR)\supp.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\des.dll"
	-@erase "$(OUTDIR)\des.exp"
	-@erase "$(OUTDIR)\des.ilk"
	-@erase "$(OUTDIR)\des.lib"
	-@erase "$(OUTDIR)\des.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "..\roken" /I "." /I "..\..\include" /I "..\..\include\win32" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "HAVE_CONFIG_H" /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /I "..\roken" /I "." /I\
 "..\..\include" /I "..\..\include\win32" /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /D "HAVE_CONFIG_H" /Fp"$(INTDIR)/des.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/"\
 /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/des.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 ..\roken\Debug\roken.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
LINK32_FLAGS=..\roken\Debug\roken.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)/des.pdb" /debug /machine:I386 /def:".\des.def"\
 /out:"$(OUTDIR)/des.dll" /implib:"$(OUTDIR)/des.lib" 
DEF_FILE= \
	".\des.def"
LINK32_OBJS= \
	"$(INTDIR)\cbc3_enc.obj" \
	"$(INTDIR)\cbc_cksm.obj" \
	"$(INTDIR)\cbc_enc.obj" \
	"$(INTDIR)\cfb64ede.obj" \
	"$(INTDIR)\cfb64enc.obj" \
	"$(INTDIR)\cfb_enc.obj" \
	"$(INTDIR)\des_enc.obj" \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\ecb3_enc.obj" \
	"$(INTDIR)\ecb_enc.obj" \
	"$(INTDIR)\ede_enc.obj" \
	"$(INTDIR)\enc_read.obj" \
	"$(INTDIR)\enc_writ.obj" \
	"$(INTDIR)\fcrypt.obj" \
	"$(INTDIR)\key_par.obj" \
	"$(INTDIR)\ncbc_enc.obj" \
	"$(INTDIR)\ofb64ede.obj" \
	"$(INTDIR)\ofb64enc.obj" \
	"$(INTDIR)\ofb_enc.obj" \
	"$(INTDIR)\passwd_dlg.obj" \
	"$(INTDIR)\pcbc_enc.obj" \
	"$(INTDIR)\qud_cksm.obj" \
	"$(INTDIR)\read_pwd.obj" \
	"$(INTDIR)\rnd_keys.obj" \
	"$(INTDIR)\rpc_enc.obj" \
	"$(INTDIR)\set_key.obj" \
	"$(INTDIR)\str2key.obj" \
	"$(INTDIR)\supp.obj"

"$(OUTDIR)\des.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "des - Win32 Release"
# Name "des - Win32 Debug"

!IF  "$(CFG)" == "des - Win32 Release"

!ELSEIF  "$(CFG)" == "des - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\des.def

!IF  "$(CFG)" == "des - Win32 Release"

!ELSEIF  "$(CFG)" == "des - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\enc_read.c
DEP_CPP_ENC_R=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\enc_read.obj" : $(SOURCE) $(DEP_CPP_ENC_R) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cbc_enc.c
DEP_CPP_CBC_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cbc_enc.obj" : $(SOURCE) $(DEP_CPP_CBC_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cbc3_enc.c
DEP_CPP_CBC3_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cbc3_enc.obj" : $(SOURCE) $(DEP_CPP_CBC3_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cfb_enc.c
DEP_CPP_CFB_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cfb_enc.obj" : $(SOURCE) $(DEP_CPP_CFB_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cfb64ede.c
DEP_CPP_CFB64=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cfb64ede.obj" : $(SOURCE) $(DEP_CPP_CFB64) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cfb64enc.c
DEP_CPP_CFB64E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cfb64enc.obj" : $(SOURCE) $(DEP_CPP_CFB64E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\dllmain.c
DEP_CPP_DLLMA=\
	"..\..\include\win32\config.h"\
	

"$(INTDIR)\dllmain.obj" : $(SOURCE) $(DEP_CPP_DLLMA) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ecb_enc.c
DEP_CPP_ECB_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	".\spr.h"\
	

"$(INTDIR)\ecb_enc.obj" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ecb3_enc.c
DEP_CPP_ECB3_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ecb3_enc.obj" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ede_enc.c
DEP_CPP_EDE_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ede_enc.obj" : $(SOURCE) $(DEP_CPP_EDE_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cbc_cksm.c
DEP_CPP_CBC_C=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\cbc_cksm.obj" : $(SOURCE) $(DEP_CPP_CBC_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\qud_cksm.c
DEP_CPP_QUD_C=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\qud_cksm.obj" : $(SOURCE) $(DEP_CPP_QUD_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\fcrypt.c
DEP_CPP_FCRYP=\
	"..\..\include\win32\config.h"\
	"..\..\include\win32\ktypes.h"\
	".\des.h"\
	".\des_locl.h"\
	".\md5.h"\
	

"$(INTDIR)\fcrypt.obj" : $(SOURCE) $(DEP_CPP_FCRYP) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\key_par.c
DEP_CPP_KEY_P=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\key_par.obj" : $(SOURCE) $(DEP_CPP_KEY_P) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ncbc_enc.c
DEP_CPP_NCBC_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ncbc_enc.obj" : $(SOURCE) $(DEP_CPP_NCBC_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ofb_enc.c
DEP_CPP_OFB_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ofb_enc.obj" : $(SOURCE) $(DEP_CPP_OFB_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ofb64ede.c
DEP_CPP_OFB64=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ofb64ede.obj" : $(SOURCE) $(DEP_CPP_OFB64) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ofb64enc.c
DEP_CPP_OFB64E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\ofb64enc.obj" : $(SOURCE) $(DEP_CPP_OFB64E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\passwd_dlg.c
DEP_CPP_PASSW=\
	"..\..\include\win32\config.h"\
	".\passwd_dlg.h"\
	

"$(INTDIR)\passwd_dlg.obj" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\pcbc_enc.c
DEP_CPP_PCBC_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\pcbc_enc.obj" : $(SOURCE) $(DEP_CPP_PCBC_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\enc_writ.c
DEP_CPP_ENC_W=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\enc_writ.obj" : $(SOURCE) $(DEP_CPP_ENC_W) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\supp.c
DEP_CPP_SUPP_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\supp.obj" : $(SOURCE) $(DEP_CPP_SUPP_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\rnd_keys.c
DEP_CPP_RND_K=\
	"..\..\include\protos.h"\
	"..\..\include\win32\config.h"\
	"..\..\include\win32\ktypes.h"\
	".\des.h"\
	".\des_locl.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

"$(INTDIR)\rnd_keys.obj" : $(SOURCE) $(DEP_CPP_RND_K) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\rpc_enc.c
DEP_CPP_RPC_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	".\des_ver.h"\
	".\rpc_des.h"\
	

"$(INTDIR)\rpc_enc.obj" : $(SOURCE) $(DEP_CPP_RPC_E) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\set_key.c
DEP_CPP_SET_K=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	".\podd.h"\
	".\sk.h"\
	

"$(INTDIR)\set_key.obj" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\str2key.c
DEP_CPP_STR2K=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\str2key.obj" : $(SOURCE) $(DEP_CPP_STR2K) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\read_pwd.c
DEP_CPP_READ_=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\read_pwd.obj" : $(SOURCE) $(DEP_CPP_READ_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\des_enc.c
DEP_CPP_DES_E=\
	"..\..\include\win32\config.h"\
	".\des.h"\
	".\des_locl.h"\
	

"$(INTDIR)\des_enc.obj" : $(SOURCE) $(DEP_CPP_DES_E) "$(INTDIR)"


# End Source File
# End Target
# End Project
################################################################################
