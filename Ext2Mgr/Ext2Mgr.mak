# Microsoft Developer Studio Generated NMAKE File, Based on Ext2Mgr.dsp
!IF "$(CFG)" == ""
CFG=Ext2Mgr - Win32 Debug
!MESSAGE No configuration specified. Defaulting to Ext2Mgr - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "Ext2Mgr - Win32 Release" && "$(CFG)" != "Ext2Mgr - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Ext2Mgr.mak" CFG="Ext2Mgr - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Ext2Mgr - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Ext2Mgr - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "Ext2Mgr - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : ".\hlp\Ext2Mgr.hm" "$(OUTDIR)\Ext2Mgr.exe" "$(OUTDIR)\Ext2Mgr.bsc"


CLEAN :
	-@erase "$(INTDIR)\DelDeadLetter.obj"
	-@erase "$(INTDIR)\DelDeadLetter.sbr"
	-@erase "$(INTDIR)\DiskBox.obj"
	-@erase "$(INTDIR)\DiskBox.sbr"
	-@erase "$(INTDIR)\Donate.obj"
	-@erase "$(INTDIR)\Donate.sbr"
	-@erase "$(INTDIR)\enumDisk.obj"
	-@erase "$(INTDIR)\enumDisk.sbr"
	-@erase "$(INTDIR)\Ext2Attribute.obj"
	-@erase "$(INTDIR)\Ext2Attribute.sbr"
	-@erase "$(INTDIR)\Ext2Mgr.obj"
	-@erase "$(INTDIR)\Ext2Mgr.pch"
	-@erase "$(INTDIR)\Ext2Mgr.res"
	-@erase "$(INTDIR)\Ext2Mgr.sbr"
	-@erase "$(INTDIR)\Ext2MgrDlg.obj"
	-@erase "$(INTDIR)\Ext2MgrDlg.sbr"
	-@erase "$(INTDIR)\HyperLink.obj"
	-@erase "$(INTDIR)\HyperLink.sbr"
	-@erase "$(INTDIR)\MountPoints.obj"
	-@erase "$(INTDIR)\MountPoints.sbr"
	-@erase "$(INTDIR)\PartBox.obj"
	-@erase "$(INTDIR)\PartBox.sbr"
	-@erase "$(INTDIR)\PartitionType.obj"
	-@erase "$(INTDIR)\PartitionType.sbr"
	-@erase "$(INTDIR)\PerfStatDlg.obj"
	-@erase "$(INTDIR)\PerfStatDlg.sbr"
	-@erase "$(INTDIR)\Properties.obj"
	-@erase "$(INTDIR)\Properties.sbr"
	-@erase "$(INTDIR)\SelectDrvLetter.obj"
	-@erase "$(INTDIR)\SelectDrvLetter.sbr"
	-@erase "$(INTDIR)\ServiceManage.obj"
	-@erase "$(INTDIR)\ServiceManage.sbr"
	-@erase "$(INTDIR)\Splash.obj"
	-@erase "$(INTDIR)\Splash.sbr"
	-@erase "$(INTDIR)\StdAfx.obj"
	-@erase "$(INTDIR)\StdAfx.sbr"
	-@erase "$(INTDIR)\SysTray.obj"
	-@erase "$(INTDIR)\SysTray.sbr"
	-@erase "$(INTDIR)\Toolbar.obj"
	-@erase "$(INTDIR)\Toolbar.sbr"
	-@erase "$(INTDIR)\TreeList.obj"
	-@erase "$(INTDIR)\TreeList.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\Ext2Mgr.bsc"
	-@erase "$(OUTDIR)\Ext2Mgr.exe"
	-@erase "hlp\Ext2Mgr.hm"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /Od /I "c:\winddk\3790\inc\w2k" /I "c:\winddk\3790\inc\ddk\w2k" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_AFXDLL" /D "_MBCS" /D "_WINNT" /D _WIN32_WINNT=0x0500 /FR"$(INTDIR)\\" /Fp"$(INTDIR)\Ext2Mgr.pch" /Yu"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\Ext2Mgr.res" /d "NDEBUG" /d "_AFXDLL" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Ext2Mgr.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\DelDeadLetter.sbr" \
	"$(INTDIR)\DiskBox.sbr" \
	"$(INTDIR)\Donate.sbr" \
	"$(INTDIR)\enumDisk.sbr" \
	"$(INTDIR)\Ext2Attribute.sbr" \
	"$(INTDIR)\Ext2Mgr.sbr" \
	"$(INTDIR)\Ext2MgrDlg.sbr" \
	"$(INTDIR)\HyperLink.sbr" \
	"$(INTDIR)\MountPoints.sbr" \
	"$(INTDIR)\PartBox.sbr" \
	"$(INTDIR)\PartitionType.sbr" \
	"$(INTDIR)\PerfStatDlg.sbr" \
	"$(INTDIR)\Properties.sbr" \
	"$(INTDIR)\SelectDrvLetter.sbr" \
	"$(INTDIR)\ServiceManage.sbr" \
	"$(INTDIR)\Splash.sbr" \
	"$(INTDIR)\StdAfx.sbr" \
	"$(INTDIR)\SysTray.sbr" \
	"$(INTDIR)\Toolbar.sbr" \
	"$(INTDIR)\TreeList.sbr"

"$(OUTDIR)\Ext2Mgr.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=ntdll.lib setupapi.lib /nologo /subsystem:windows /incremental:no /pdb:"$(OUTDIR)\Ext2Mgr.pdb" /machine:I386 /out:"$(OUTDIR)\Ext2Mgr.exe" /libpath:"c:\winddk\3790\lib\w2k\i386" 
LINK32_OBJS= \
	"$(INTDIR)\DelDeadLetter.obj" \
	"$(INTDIR)\DiskBox.obj" \
	"$(INTDIR)\Donate.obj" \
	"$(INTDIR)\enumDisk.obj" \
	"$(INTDIR)\Ext2Attribute.obj" \
	"$(INTDIR)\Ext2Mgr.obj" \
	"$(INTDIR)\Ext2MgrDlg.obj" \
	"$(INTDIR)\HyperLink.obj" \
	"$(INTDIR)\MountPoints.obj" \
	"$(INTDIR)\PartBox.obj" \
	"$(INTDIR)\PartitionType.obj" \
	"$(INTDIR)\PerfStatDlg.obj" \
	"$(INTDIR)\Properties.obj" \
	"$(INTDIR)\SelectDrvLetter.obj" \
	"$(INTDIR)\ServiceManage.obj" \
	"$(INTDIR)\Splash.obj" \
	"$(INTDIR)\StdAfx.obj" \
	"$(INTDIR)\SysTray.obj" \
	"$(INTDIR)\Toolbar.obj" \
	"$(INTDIR)\TreeList.obj" \
	"$(INTDIR)\Ext2Mgr.res"

"$(OUTDIR)\Ext2Mgr.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Ext2Mgr - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : ".\hlp\Ext2Mgr.hm" "$(OUTDIR)\Ext2Mgr.exe" "$(OUTDIR)\Ext2Mgr.bsc"


CLEAN :
	-@erase "$(INTDIR)\DelDeadLetter.obj"
	-@erase "$(INTDIR)\DelDeadLetter.sbr"
	-@erase "$(INTDIR)\DiskBox.obj"
	-@erase "$(INTDIR)\DiskBox.sbr"
	-@erase "$(INTDIR)\Donate.obj"
	-@erase "$(INTDIR)\Donate.sbr"
	-@erase "$(INTDIR)\enumDisk.obj"
	-@erase "$(INTDIR)\enumDisk.sbr"
	-@erase "$(INTDIR)\Ext2Attribute.obj"
	-@erase "$(INTDIR)\Ext2Attribute.sbr"
	-@erase "$(INTDIR)\Ext2Mgr.obj"
	-@erase "$(INTDIR)\Ext2Mgr.pch"
	-@erase "$(INTDIR)\Ext2Mgr.res"
	-@erase "$(INTDIR)\Ext2Mgr.sbr"
	-@erase "$(INTDIR)\Ext2MgrDlg.obj"
	-@erase "$(INTDIR)\Ext2MgrDlg.sbr"
	-@erase "$(INTDIR)\HyperLink.obj"
	-@erase "$(INTDIR)\HyperLink.sbr"
	-@erase "$(INTDIR)\MountPoints.obj"
	-@erase "$(INTDIR)\MountPoints.sbr"
	-@erase "$(INTDIR)\PartBox.obj"
	-@erase "$(INTDIR)\PartBox.sbr"
	-@erase "$(INTDIR)\PartitionType.obj"
	-@erase "$(INTDIR)\PartitionType.sbr"
	-@erase "$(INTDIR)\PerfStatDlg.obj"
	-@erase "$(INTDIR)\PerfStatDlg.sbr"
	-@erase "$(INTDIR)\Properties.obj"
	-@erase "$(INTDIR)\Properties.sbr"
	-@erase "$(INTDIR)\SelectDrvLetter.obj"
	-@erase "$(INTDIR)\SelectDrvLetter.sbr"
	-@erase "$(INTDIR)\ServiceManage.obj"
	-@erase "$(INTDIR)\ServiceManage.sbr"
	-@erase "$(INTDIR)\Splash.obj"
	-@erase "$(INTDIR)\Splash.sbr"
	-@erase "$(INTDIR)\StdAfx.obj"
	-@erase "$(INTDIR)\StdAfx.sbr"
	-@erase "$(INTDIR)\SysTray.obj"
	-@erase "$(INTDIR)\SysTray.sbr"
	-@erase "$(INTDIR)\Toolbar.obj"
	-@erase "$(INTDIR)\Toolbar.sbr"
	-@erase "$(INTDIR)\TreeList.obj"
	-@erase "$(INTDIR)\TreeList.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\Ext2Mgr.bsc"
	-@erase "$(OUTDIR)\Ext2Mgr.exe"
	-@erase "$(OUTDIR)\Ext2Mgr.ilk"
	-@erase "$(OUTDIR)\Ext2Mgr.pdb"
	-@erase "hlp\Ext2Mgr.hm"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /w /W0 /Gm /GX /ZI /Od /I "c:\winddk\3790\inc\w2k" /I "c:\winddk\3790\inc\ddk\w2k" /D "_DEBUG" /D "_WINDOWS" /D "_AFXDLL" /D "_MBCS" /D "_WINNT" /D "WIN32" /D _WIN32_WINNT=0x0500 /FR"$(INTDIR)\\" /Fp"$(INTDIR)\Ext2Mgr.pch" /Yu"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\Ext2Mgr.res" /d "_DEBUG" /d "_AFXDLL" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Ext2Mgr.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\DelDeadLetter.sbr" \
	"$(INTDIR)\DiskBox.sbr" \
	"$(INTDIR)\Donate.sbr" \
	"$(INTDIR)\enumDisk.sbr" \
	"$(INTDIR)\Ext2Attribute.sbr" \
	"$(INTDIR)\Ext2Mgr.sbr" \
	"$(INTDIR)\Ext2MgrDlg.sbr" \
	"$(INTDIR)\HyperLink.sbr" \
	"$(INTDIR)\MountPoints.sbr" \
	"$(INTDIR)\PartBox.sbr" \
	"$(INTDIR)\PartitionType.sbr" \
	"$(INTDIR)\PerfStatDlg.sbr" \
	"$(INTDIR)\Properties.sbr" \
	"$(INTDIR)\SelectDrvLetter.sbr" \
	"$(INTDIR)\ServiceManage.sbr" \
	"$(INTDIR)\Splash.sbr" \
	"$(INTDIR)\StdAfx.sbr" \
	"$(INTDIR)\SysTray.sbr" \
	"$(INTDIR)\Toolbar.sbr" \
	"$(INTDIR)\TreeList.sbr"

"$(OUTDIR)\Ext2Mgr.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=ntdll.lib setupapi.lib /nologo /subsystem:windows /incremental:yes /pdb:"$(OUTDIR)\Ext2Mgr.pdb" /debug /machine:I386 /out:"$(OUTDIR)\Ext2Mgr.exe" /libpath:"c:\winddk\3790\lib\w2k\i386" 
LINK32_OBJS= \
	"$(INTDIR)\DelDeadLetter.obj" \
	"$(INTDIR)\DiskBox.obj" \
	"$(INTDIR)\Donate.obj" \
	"$(INTDIR)\enumDisk.obj" \
	"$(INTDIR)\Ext2Attribute.obj" \
	"$(INTDIR)\Ext2Mgr.obj" \
	"$(INTDIR)\Ext2MgrDlg.obj" \
	"$(INTDIR)\HyperLink.obj" \
	"$(INTDIR)\MountPoints.obj" \
	"$(INTDIR)\PartBox.obj" \
	"$(INTDIR)\PartitionType.obj" \
	"$(INTDIR)\PerfStatDlg.obj" \
	"$(INTDIR)\Properties.obj" \
	"$(INTDIR)\SelectDrvLetter.obj" \
	"$(INTDIR)\ServiceManage.obj" \
	"$(INTDIR)\Splash.obj" \
	"$(INTDIR)\StdAfx.obj" \
	"$(INTDIR)\SysTray.obj" \
	"$(INTDIR)\Toolbar.obj" \
	"$(INTDIR)\TreeList.obj" \
	"$(INTDIR)\Ext2Mgr.res"

"$(OUTDIR)\Ext2Mgr.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("Ext2Mgr.dep")
!INCLUDE "Ext2Mgr.dep"
!ELSE 
!MESSAGE Warning: cannot find "Ext2Mgr.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "Ext2Mgr - Win32 Release" || "$(CFG)" == "Ext2Mgr - Win32 Debug"
SOURCE=.\DelDeadLetter.cpp

"$(INTDIR)\DelDeadLetter.obj"	"$(INTDIR)\DelDeadLetter.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\DiskBox.cpp

"$(INTDIR)\DiskBox.obj"	"$(INTDIR)\DiskBox.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Donate.cpp

"$(INTDIR)\Donate.obj"	"$(INTDIR)\Donate.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\enumDisk.cpp

"$(INTDIR)\enumDisk.obj"	"$(INTDIR)\enumDisk.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Ext2Attribute.cpp

"$(INTDIR)\Ext2Attribute.obj"	"$(INTDIR)\Ext2Attribute.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Ext2Mgr.cpp

"$(INTDIR)\Ext2Mgr.obj"	"$(INTDIR)\Ext2Mgr.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Ext2Mgr.rc

"$(INTDIR)\Ext2Mgr.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE)


SOURCE=.\Ext2MgrDlg.cpp

"$(INTDIR)\Ext2MgrDlg.obj"	"$(INTDIR)\Ext2MgrDlg.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\HyperLink.cpp

"$(INTDIR)\HyperLink.obj"	"$(INTDIR)\HyperLink.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\MountPoints.cpp

"$(INTDIR)\MountPoints.obj"	"$(INTDIR)\MountPoints.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\PartBox.cpp

"$(INTDIR)\PartBox.obj"	"$(INTDIR)\PartBox.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\PartitionType.cpp

"$(INTDIR)\PartitionType.obj"	"$(INTDIR)\PartitionType.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\PerfStatDlg.cpp

"$(INTDIR)\PerfStatDlg.obj"	"$(INTDIR)\PerfStatDlg.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Properties.cpp

"$(INTDIR)\Properties.obj"	"$(INTDIR)\Properties.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\SelectDrvLetter.cpp

"$(INTDIR)\SelectDrvLetter.obj"	"$(INTDIR)\SelectDrvLetter.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\ServiceManage.cpp

"$(INTDIR)\ServiceManage.obj"	"$(INTDIR)\ServiceManage.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Splash.cpp

"$(INTDIR)\Splash.obj"	"$(INTDIR)\Splash.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\StdAfx.cpp

!IF  "$(CFG)" == "Ext2Mgr - Win32 Release"

CPP_SWITCHES=/nologo /MD /W3 /GX /Od /I "c:\winddk\3790\inc\w2k" /I "c:\winddk\3790\inc\ddk\w2k" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_AFXDLL" /D "_MBCS" /D "_WINNT" /D _WIN32_WINNT=0x0500 /FR"$(INTDIR)\\" /Fp"$(INTDIR)\Ext2Mgr.pch" /Yc"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

"$(INTDIR)\StdAfx.obj"	"$(INTDIR)\StdAfx.sbr"	"$(INTDIR)\Ext2Mgr.pch" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "Ext2Mgr - Win32 Debug"

CPP_SWITCHES=/nologo /MDd /w /W0 /Gm /GX /ZI /Od /I "c:\winddk\3790\inc\w2k" /I "c:\winddk\3790\inc\ddk\w2k" /D "_DEBUG" /D "_WINDOWS" /D "_AFXDLL" /D "_MBCS" /D "_WINNT" /D "WIN32" /D _WIN32_WINNT=0x0500 /FR"$(INTDIR)\\" /Fp"$(INTDIR)\Ext2Mgr.pch" /Yc"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

"$(INTDIR)\StdAfx.obj"	"$(INTDIR)\StdAfx.sbr"	"$(INTDIR)\Ext2Mgr.pch" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ENDIF 

SOURCE=.\SysTray.cpp

"$(INTDIR)\SysTray.obj"	"$(INTDIR)\SysTray.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Toolbar.cpp

"$(INTDIR)\Toolbar.obj"	"$(INTDIR)\Toolbar.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\TreeList.cpp

"$(INTDIR)\TreeList.obj"	"$(INTDIR)\TreeList.sbr" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\Ext2Mgr.pch"


SOURCE=.\Resource.h

!IF  "$(CFG)" == "Ext2Mgr - Win32 Release"

TargetName=Ext2Mgr
InputPath=.\Resource.h

".\hlp\Ext2Mgr.hm" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	echo. >"hlp\$(TargetName).hm" 
	echo // Commands (ID_* and IDM_*) >>"hlp\$(TargetName).hm" 
	makehm ID_,HID_,0x10000 IDM_,HIDM_,0x10000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Prompts (IDP_*) >>"hlp\$(TargetName).hm" 
	makehm IDP_,HIDP_,0x30000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Resources (IDR_*) >>"hlp\$(TargetName).hm" 
	makehm IDR_,HIDR_,0x20000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Dialogs (IDD_*) >>"hlp\$(TargetName).hm" 
	makehm IDD_,HIDD_,0x20000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Frame Controls (IDW_*) >>"hlp\$(TargetName).hm" 
	makehm IDW_,HIDW_,0x50000 resource.h >>"hlp\$(TargetName).hm" 
<< 
	

!ELSEIF  "$(CFG)" == "Ext2Mgr - Win32 Debug"

TargetName=Ext2Mgr
InputPath=.\Resource.h

".\hlp\Ext2Mgr.hm" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	echo. >"hlp\$(TargetName).hm" 
	echo // Commands (ID_* and IDM_*) >>"hlp\$(TargetName).hm" 
	makehm ID_,HID_,0x10000 IDM_,HIDM_,0x10000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Prompts (IDP_*) >>"hlp\$(TargetName).hm" 
	makehm IDP_,HIDP_,0x30000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Resources (IDR_*) >>"hlp\$(TargetName).hm" 
	makehm IDR_,HIDR_,0x20000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Dialogs (IDD_*) >>"hlp\$(TargetName).hm" 
	makehm IDD_,HIDD_,0x20000 resource.h >>"hlp\$(TargetName).hm" 
	echo. >>"hlp\$(TargetName).hm" 
	echo // Frame Controls (IDW_*) >>"hlp\$(TargetName).hm" 
	makehm IDW_,HIDW_,0x50000 resource.h >>"hlp\$(TargetName).hm" 
<< 
	

!ENDIF 


!ENDIF 

