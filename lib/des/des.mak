# Microsoft Developer Studio Generated NMAKE File, Format Version 40001
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
MTL=mktyplib.exe
CPP=cl.exe
RSC=rc.exe

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
	-@erase ".\Release\des.dll"
	-@erase ".\Release\ofb64enc.obj"
	-@erase ".\Release\supp.obj"
	-@erase ".\Release\ecb_enc.obj"
	-@erase ".\Release\rand_key.obj"
	-@erase ".\Release\cfb64ede.obj"
	-@erase ".\Release\gettimeofday.obj"
	-@erase ".\Release\md5.obj"
	-@erase ".\Release\cbc_enc.obj"
	-@erase ".\Release\ofb64ede.obj"
	-@erase ".\Release\cbc3_enc.obj"
	-@erase ".\Release\cbc_cksm.obj"
	-@erase ".\Release\pcbc_enc.obj"
	-@erase ".\Release\str2key.obj"
	-@erase ".\Release\enc_writ.obj"
	-@erase ".\Release\read_pwd.obj"
	-@erase ".\Release\cfb_enc.obj"
	-@erase ".\Release\ncbc_enc.obj"
	-@erase ".\Release\speed.obj"
	-@erase ".\Release\key_par.obj"
	-@erase ".\Release\qud_cksm.obj"
	-@erase ".\Release\rnd_keys.obj"
	-@erase ".\Release\rpc_enc.obj"
	-@erase ".\Release\ofb_enc.obj"
	-@erase ".\Release\passwd_dlg.obj"
	-@erase ".\Release\enc_read.obj"
	-@erase ".\Release\fcrypt.obj"
	-@erase ".\Release\ede_enc.obj"
	-@erase ".\Release\cfb64enc.obj"
	-@erase ".\Release\set_key.obj"
	-@erase ".\Release\ecb3_enc.obj"
	-@erase ".\Release\passwd_dialog.res"
	-@erase ".\Release\des.lib"
	-@erase ".\Release\des.exp"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/des.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x41d /d "NDEBUG"
# ADD RSC /l 0x41d /d "NDEBUG"
RSC_PROJ=/l 0x41d /fo"$(INTDIR)/passwd_dialog.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/des.bsc" 
BSC32_SBRS=
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)/des.pdb" /machine:I386 /def:".\des.def"\
 /out:"$(OUTDIR)/des.dll" /implib:"$(OUTDIR)/des.lib" 
DEF_FILE= \
	".\des.def"
LINK32_OBJS= \
	"$(INTDIR)/ofb64enc.obj" \
	"$(INTDIR)/supp.obj" \
	"$(INTDIR)/ecb_enc.obj" \
	"$(INTDIR)/rand_key.obj" \
	"$(INTDIR)/cfb64ede.obj" \
	"$(INTDIR)/gettimeofday.obj" \
	"$(INTDIR)/md5.obj" \
	"$(INTDIR)/cbc_enc.obj" \
	"$(INTDIR)/ofb64ede.obj" \
	"$(INTDIR)/cbc3_enc.obj" \
	"$(INTDIR)/cbc_cksm.obj" \
	"$(INTDIR)/pcbc_enc.obj" \
	"$(INTDIR)/str2key.obj" \
	"$(INTDIR)/enc_writ.obj" \
	"$(INTDIR)/read_pwd.obj" \
	"$(INTDIR)/cfb_enc.obj" \
	"$(INTDIR)/ncbc_enc.obj" \
	"$(INTDIR)/speed.obj" \
	"$(INTDIR)/key_par.obj" \
	"$(INTDIR)/qud_cksm.obj" \
	"$(INTDIR)/rnd_keys.obj" \
	"$(INTDIR)/rpc_enc.obj" \
	"$(INTDIR)/ofb_enc.obj" \
	"$(INTDIR)/passwd_dlg.obj" \
	"$(INTDIR)/enc_read.obj" \
	"$(INTDIR)/fcrypt.obj" \
	"$(INTDIR)/ede_enc.obj" \
	"$(INTDIR)/cfb64enc.obj" \
	"$(INTDIR)/set_key.obj" \
	"$(INTDIR)/ecb3_enc.obj" \
	"$(INTDIR)/passwd_dialog.res"

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

ALL : "$(OUTDIR)\des.dll" "$(OUTDIR)\des.bsc"

CLEAN : 
	-@erase ".\Debug\vc40.pdb"
	-@erase ".\Debug\vc40.idb"
	-@erase ".\Debug\des.bsc"
	-@erase ".\Debug\rpc_enc.sbr"
	-@erase ".\Debug\ofb_enc.sbr"
	-@erase ".\Debug\ecb3_enc.sbr"
	-@erase ".\Debug\ofb64enc.sbr"
	-@erase ".\Debug\gettimeofday.sbr"
	-@erase ".\Debug\read_pwd.sbr"
	-@erase ".\Debug\fcrypt.sbr"
	-@erase ".\Debug\ede_enc.sbr"
	-@erase ".\Debug\set_key.sbr"
	-@erase ".\Debug\qud_cksm.sbr"
	-@erase ".\Debug\rand_key.sbr"
	-@erase ".\Debug\passwd_dlg.sbr"
	-@erase ".\Debug\ecb_enc.sbr"
	-@erase ".\Debug\ofb64ede.sbr"
	-@erase ".\Debug\enc_read.sbr"
	-@erase ".\Debug\key_par.sbr"
	-@erase ".\Debug\cbc3_enc.sbr"
	-@erase ".\Debug\cbc_cksm.sbr"
	-@erase ".\Debug\speed.sbr"
	-@erase ".\Debug\supp.sbr"
	-@erase ".\Debug\pcbc_enc.sbr"
	-@erase ".\Debug\cfb64enc.sbr"
	-@erase ".\Debug\enc_writ.sbr"
	-@erase ".\Debug\md5.sbr"
	-@erase ".\Debug\cbc_enc.sbr"
	-@erase ".\Debug\ncbc_enc.sbr"
	-@erase ".\Debug\rnd_keys.sbr"
	-@erase ".\Debug\str2key.sbr"
	-@erase ".\Debug\cfb_enc.sbr"
	-@erase ".\Debug\cfb64ede.sbr"
	-@erase ".\Debug\des.dll"
	-@erase ".\Debug\str2key.obj"
	-@erase ".\Debug\cfb_enc.obj"
	-@erase ".\Debug\cfb64ede.obj"
	-@erase ".\Debug\rpc_enc.obj"
	-@erase ".\Debug\ofb_enc.obj"
	-@erase ".\Debug\ecb3_enc.obj"
	-@erase ".\Debug\ofb64enc.obj"
	-@erase ".\Debug\gettimeofday.obj"
	-@erase ".\Debug\read_pwd.obj"
	-@erase ".\Debug\fcrypt.obj"
	-@erase ".\Debug\ede_enc.obj"
	-@erase ".\Debug\set_key.obj"
	-@erase ".\Debug\qud_cksm.obj"
	-@erase ".\Debug\rand_key.obj"
	-@erase ".\Debug\passwd_dlg.obj"
	-@erase ".\Debug\ecb_enc.obj"
	-@erase ".\Debug\ofb64ede.obj"
	-@erase ".\Debug\enc_read.obj"
	-@erase ".\Debug\key_par.obj"
	-@erase ".\Debug\cbc3_enc.obj"
	-@erase ".\Debug\cbc_cksm.obj"
	-@erase ".\Debug\speed.obj"
	-@erase ".\Debug\supp.obj"
	-@erase ".\Debug\pcbc_enc.obj"
	-@erase ".\Debug\cfb64enc.obj"
	-@erase ".\Debug\enc_writ.obj"
	-@erase ".\Debug\md5.obj"
	-@erase ".\Debug\cbc_enc.obj"
	-@erase ".\Debug\ncbc_enc.obj"
	-@erase ".\Debug\rnd_keys.obj"
	-@erase ".\Debug\passwd_dialog.res"
	-@erase ".\Debug\des.ilk"
	-@erase ".\Debug\des.lib"
	-@erase ".\Debug\des.exp"
	-@erase ".\Debug\des.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /FR"$(INTDIR)/" /Fp"$(INTDIR)/des.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\Debug/
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x41d /d "_DEBUG"
# ADD RSC /l 0x41d /d "_DEBUG"
RSC_PROJ=/l 0x41d /fo"$(INTDIR)/passwd_dialog.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/des.bsc" 
BSC32_SBRS= \
	"$(INTDIR)/rpc_enc.sbr" \
	"$(INTDIR)/ofb_enc.sbr" \
	"$(INTDIR)/ecb3_enc.sbr" \
	"$(INTDIR)/ofb64enc.sbr" \
	"$(INTDIR)/gettimeofday.sbr" \
	"$(INTDIR)/read_pwd.sbr" \
	"$(INTDIR)/fcrypt.sbr" \
	"$(INTDIR)/ede_enc.sbr" \
	"$(INTDIR)/set_key.sbr" \
	"$(INTDIR)/qud_cksm.sbr" \
	"$(INTDIR)/rand_key.sbr" \
	"$(INTDIR)/passwd_dlg.sbr" \
	"$(INTDIR)/ecb_enc.sbr" \
	"$(INTDIR)/ofb64ede.sbr" \
	"$(INTDIR)/enc_read.sbr" \
	"$(INTDIR)/key_par.sbr" \
	"$(INTDIR)/cbc3_enc.sbr" \
	"$(INTDIR)/cbc_cksm.sbr" \
	"$(INTDIR)/speed.sbr" \
	"$(INTDIR)/supp.sbr" \
	"$(INTDIR)/pcbc_enc.sbr" \
	"$(INTDIR)/cfb64enc.sbr" \
	"$(INTDIR)/enc_writ.sbr" \
	"$(INTDIR)/md5.sbr" \
	"$(INTDIR)/cbc_enc.sbr" \
	"$(INTDIR)/ncbc_enc.sbr" \
	"$(INTDIR)/rnd_keys.sbr" \
	"$(INTDIR)/str2key.sbr" \
	"$(INTDIR)/cfb_enc.sbr" \
	"$(INTDIR)/cfb64ede.sbr"

"$(OUTDIR)\des.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)/des.pdb" /debug /machine:I386 /def:".\des.def"\
 /out:"$(OUTDIR)/des.dll" /implib:"$(OUTDIR)/des.lib" 
DEF_FILE= \
	".\des.def"
LINK32_OBJS= \
	"$(INTDIR)/str2key.obj" \
	"$(INTDIR)/cfb_enc.obj" \
	"$(INTDIR)/cfb64ede.obj" \
	"$(INTDIR)/rpc_enc.obj" \
	"$(INTDIR)/ofb_enc.obj" \
	"$(INTDIR)/ecb3_enc.obj" \
	"$(INTDIR)/ofb64enc.obj" \
	"$(INTDIR)/gettimeofday.obj" \
	"$(INTDIR)/read_pwd.obj" \
	"$(INTDIR)/fcrypt.obj" \
	"$(INTDIR)/ede_enc.obj" \
	"$(INTDIR)/set_key.obj" \
	"$(INTDIR)/qud_cksm.obj" \
	"$(INTDIR)/rand_key.obj" \
	"$(INTDIR)/passwd_dlg.obj" \
	"$(INTDIR)/ecb_enc.obj" \
	"$(INTDIR)/ofb64ede.obj" \
	"$(INTDIR)/enc_read.obj" \
	"$(INTDIR)/key_par.obj" \
	"$(INTDIR)/cbc3_enc.obj" \
	"$(INTDIR)/cbc_cksm.obj" \
	"$(INTDIR)/speed.obj" \
	"$(INTDIR)/supp.obj" \
	"$(INTDIR)/pcbc_enc.obj" \
	"$(INTDIR)/cfb64enc.obj" \
	"$(INTDIR)/enc_writ.obj" \
	"$(INTDIR)/md5.obj" \
	"$(INTDIR)/cbc_enc.obj" \
	"$(INTDIR)/ncbc_enc.obj" \
	"$(INTDIR)/rnd_keys.obj" \
	"$(INTDIR)/passwd_dialog.res"

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

SOURCE=.\des\supp.c
DEP_CPP_SUPP_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_SUPP_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\supp.obj" : $(SOURCE) $(DEP_CPP_SUPP_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\supp.obj" : $(SOURCE) $(DEP_CPP_SUPP_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\supp.sbr" : $(SOURCE) $(DEP_CPP_SUPP_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\str2key.c
DEP_CPP_STR2K=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_STR2K=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\str2key.obj" : $(SOURCE) $(DEP_CPP_STR2K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\str2key.obj" : $(SOURCE) $(DEP_CPP_STR2K) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\str2key.sbr" : $(SOURCE) $(DEP_CPP_STR2K) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\speed.c
DEP_CPP_SPEED=\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	{$(INCLUDE)}"\sys\TIMEB.H"\
	{$(INCLUDE)}"\des.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\speed.obj" : $(SOURCE) $(DEP_CPP_SPEED) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\speed.obj" : $(SOURCE) $(DEP_CPP_SPEED) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\speed.sbr" : $(SOURCE) $(DEP_CPP_SPEED) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\set_key.c
DEP_CPP_SET_K=\
	{$(INCLUDE)}"\des_locl.h"\
	".\des\podd.h"\
	".\des\sk.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_SET_K=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\set_key.obj" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\set_key.obj" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\set_key.sbr" : $(SOURCE) $(DEP_CPP_SET_K) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\rpc_enc.c
DEP_CPP_RPC_E=\
	".\des\rpc_des.h"\
	{$(INCLUDE)}"\des_locl.h"\
	".\des\version.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_RPC_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\rpc_enc.obj" : $(SOURCE) $(DEP_CPP_RPC_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\rpc_enc.obj" : $(SOURCE) $(DEP_CPP_RPC_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\rpc_enc.sbr" : $(SOURCE) $(DEP_CPP_RPC_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\rnd_keys.c
DEP_CPP_RND_K=\
	{$(INCLUDE)}"\protos.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\sys\bitypes.H"\
	{$(INCLUDE)}"\sys\time.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	{$(INCLUDE)}"\sys\socket.h"\
	{$(INCLUDE)}"\netinet\in.h"\
	{$(INCLUDE)}"\netdb.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_RND_K=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\rnd_keys.obj" : $(SOURCE) $(DEP_CPP_RND_K) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\rnd_keys.obj" : $(SOURCE) $(DEP_CPP_RND_K) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\rnd_keys.sbr" : $(SOURCE) $(DEP_CPP_RND_K) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\read_pwd.c
DEP_CPP_READ_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\winlocl\passwd_dlg.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_READ_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\read_pwd.obj" : $(SOURCE) $(DEP_CPP_READ_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\read_pwd.obj" : $(SOURCE) $(DEP_CPP_READ_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\read_pwd.sbr" : $(SOURCE) $(DEP_CPP_READ_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\rand_key.c
DEP_CPP_RAND_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_RAND_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\rand_key.obj" : $(SOURCE) $(DEP_CPP_RAND_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\rand_key.obj" : $(SOURCE) $(DEP_CPP_RAND_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\rand_key.sbr" : $(SOURCE) $(DEP_CPP_RAND_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\qud_cksm.c
DEP_CPP_QUD_C=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_QUD_C=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\qud_cksm.obj" : $(SOURCE) $(DEP_CPP_QUD_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\qud_cksm.obj" : $(SOURCE) $(DEP_CPP_QUD_C) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\qud_cksm.sbr" : $(SOURCE) $(DEP_CPP_QUD_C) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\pcbc_enc.c
DEP_CPP_PCBC_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_PCBC_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\pcbc_enc.obj" : $(SOURCE) $(DEP_CPP_PCBC_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\pcbc_enc.obj" : $(SOURCE) $(DEP_CPP_PCBC_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\pcbc_enc.sbr" : $(SOURCE) $(DEP_CPP_PCBC_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ofb64enc.c
DEP_CPP_OFB64=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_OFB64=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ofb64enc.obj" : $(SOURCE) $(DEP_CPP_OFB64) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ofb64enc.obj" : $(SOURCE) $(DEP_CPP_OFB64) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ofb64enc.sbr" : $(SOURCE) $(DEP_CPP_OFB64) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ofb64ede.c
DEP_CPP_OFB64E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_OFB64E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ofb64ede.obj" : $(SOURCE) $(DEP_CPP_OFB64E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ofb64ede.obj" : $(SOURCE) $(DEP_CPP_OFB64E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ofb64ede.sbr" : $(SOURCE) $(DEP_CPP_OFB64E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ofb_enc.c
DEP_CPP_OFB_E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_OFB_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ofb_enc.obj" : $(SOURCE) $(DEP_CPP_OFB_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ofb_enc.obj" : $(SOURCE) $(DEP_CPP_OFB_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ofb_enc.sbr" : $(SOURCE) $(DEP_CPP_OFB_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ncbc_enc.c
DEP_CPP_NCBC_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_NCBC_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ncbc_enc.obj" : $(SOURCE) $(DEP_CPP_NCBC_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ncbc_enc.obj" : $(SOURCE) $(DEP_CPP_NCBC_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ncbc_enc.sbr" : $(SOURCE) $(DEP_CPP_NCBC_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\md5.c
DEP_CPP_MD5_C=\
	{$(INCLUDE)}"\sys\cdefs.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	{$(INCLUDE)}"\sys\bitypes.H"\
	".\des\md5.h"\
	
NODEP_CPP_MD5_C=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\md5.obj" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\md5.obj" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\md5.sbr" : $(SOURCE) $(DEP_CPP_MD5_C) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\key_par.c
DEP_CPP_KEY_P=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_KEY_P=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\key_par.obj" : $(SOURCE) $(DEP_CPP_KEY_P) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\key_par.obj" : $(SOURCE) $(DEP_CPP_KEY_P) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\key_par.sbr" : $(SOURCE) $(DEP_CPP_KEY_P) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\fcrypt.c

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\fcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\fcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\fcrypt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\enc_writ.c
DEP_CPP_ENC_W=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_ENC_W=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\enc_writ.obj" : $(SOURCE) $(DEP_CPP_ENC_W) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\enc_writ.obj" : $(SOURCE) $(DEP_CPP_ENC_W) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\enc_writ.sbr" : $(SOURCE) $(DEP_CPP_ENC_W) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\enc_read.c
DEP_CPP_ENC_R=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_ENC_R=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\enc_read.obj" : $(SOURCE) $(DEP_CPP_ENC_R) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\enc_read.obj" : $(SOURCE) $(DEP_CPP_ENC_R) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\enc_read.sbr" : $(SOURCE) $(DEP_CPP_ENC_R) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ede_enc.c
DEP_CPP_EDE_E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_EDE_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ede_enc.obj" : $(SOURCE) $(DEP_CPP_EDE_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ede_enc.obj" : $(SOURCE) $(DEP_CPP_EDE_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ede_enc.sbr" : $(SOURCE) $(DEP_CPP_EDE_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ecb3_enc.c
DEP_CPP_ECB3_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_ECB3_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ecb3_enc.obj" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ecb3_enc.obj" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ecb3_enc.sbr" : $(SOURCE) $(DEP_CPP_ECB3_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\ecb_enc.c
DEP_CPP_ECB_E=\
	{$(INCLUDE)}"\des_locl.h"\
	".\des\spr.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_ECB_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\ecb_enc.obj" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ecb_enc.obj" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ecb_enc.sbr" : $(SOURCE) $(DEP_CPP_ECB_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cfb64enc.c
DEP_CPP_CFB64=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CFB64=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cfb64enc.obj" : $(SOURCE) $(DEP_CPP_CFB64) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cfb64enc.obj" : $(SOURCE) $(DEP_CPP_CFB64) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cfb64enc.sbr" : $(SOURCE) $(DEP_CPP_CFB64) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cfb64ede.c
DEP_CPP_CFB64E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CFB64E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cfb64ede.obj" : $(SOURCE) $(DEP_CPP_CFB64E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cfb64ede.obj" : $(SOURCE) $(DEP_CPP_CFB64E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cfb64ede.sbr" : $(SOURCE) $(DEP_CPP_CFB64E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cfb_enc.c
DEP_CPP_CFB_E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CFB_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cfb_enc.obj" : $(SOURCE) $(DEP_CPP_CFB_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cfb_enc.obj" : $(SOURCE) $(DEP_CPP_CFB_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cfb_enc.sbr" : $(SOURCE) $(DEP_CPP_CFB_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cbc3_enc.c
DEP_CPP_CBC3_=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CBC3_=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cbc3_enc.obj" : $(SOURCE) $(DEP_CPP_CBC3_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cbc3_enc.obj" : $(SOURCE) $(DEP_CPP_CBC3_) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cbc3_enc.sbr" : $(SOURCE) $(DEP_CPP_CBC3_) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cbc_enc.c
DEP_CPP_CBC_E=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CBC_E=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cbc_enc.obj" : $(SOURCE) $(DEP_CPP_CBC_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cbc_enc.obj" : $(SOURCE) $(DEP_CPP_CBC_E) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cbc_enc.sbr" : $(SOURCE) $(DEP_CPP_CBC_E) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des\cbc_cksm.c
DEP_CPP_CBC_C=\
	{$(INCLUDE)}"\des_locl.h"\
	{$(INCLUDE)}"\des.h"\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	
NODEP_CPP_CBC_C=\
	".\des\config.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\cbc_cksm.obj" : $(SOURCE) $(DEP_CPP_CBC_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\cbc_cksm.obj" : $(SOURCE) $(DEP_CPP_CBC_C) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\cbc_cksm.sbr" : $(SOURCE) $(DEP_CPP_CBC_C) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\winlocl\passwd_dlg.c
DEP_CPP_PASSW=\
	{$(INCLUDE)}"\winlocl\passwd_dlg.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\passwd_dlg.obj" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\passwd_dlg.obj" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\passwd_dlg.sbr" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\winlocl\passwd_dialog.rc

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\passwd_dialog.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x41d /fo"$(INTDIR)/passwd_dialog.res" /i "winlocl" /d "NDEBUG"\
 $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


"$(INTDIR)\passwd_dialog.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x41d /fo"$(INTDIR)/passwd_dialog.res" /i "winlocl" /d "_DEBUG"\
 $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\des.def

!IF  "$(CFG)" == "des - Win32 Release"

!ELSEIF  "$(CFG)" == "des - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE="\USERS\d93-jka\Projects\winlocl_src\gettimeofday.c"
DEP_CPP_GETTI=\
	{$(INCLUDE)}"\winlocl\winlocl.h"\
	

!IF  "$(CFG)" == "des - Win32 Release"


"$(INTDIR)\gettimeofday.obj" : $(SOURCE) $(DEP_CPP_GETTI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "des - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\gettimeofday.obj" : $(SOURCE) $(DEP_CPP_GETTI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\gettimeofday.sbr" : $(SOURCE) $(DEP_CPP_GETTI) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
