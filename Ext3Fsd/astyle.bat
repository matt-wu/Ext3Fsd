for /R %%a in (*.c;*.h;) do astyle.exe --indent=spaces=4 %%a
for /R %%a in (*.c;*.h;DIRS;sources;) do dos2unix %%a 
