del /s *.log
del /s *.wrn
del /s *.err
del /s *.obj
del /s *.sbr
del /s *.sys
del /s *.exp
del /s *.idb
del /s *.ilk
del /s BuildLog.htm
del /s *.mac
REM to avoid pthreads lib deletion
del /s *.lib
del /s *.pdb
c:\cygwin\bin\find . -name objchk* -exec rm -rf {} +
c:\cygwin\bin\find . -name objfre* -exec rm -rf {} +
