
set BROWSER_INFO_SUPPORTED=1

build -ceZ
"c:\Program Files (x86)\Microsoft Visual Studio\vc98\bin\BSCMAKE.EXE" /n /o winnet\chk\i386\Ext3Fsd.bsc @sbrfiles 

@del /s *.sbr > NUL
