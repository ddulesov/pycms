setlocal
set ACTION=%1
set ARG=%2

if "%ACTION%"=="run"  (
	set ARG="-i" 
	goto:run 
)

del _pycms.pyd

c:\Python37\python.exe setup.py  build
IF ERRORLEVEL 1 GOTO:eof
  
copy build\lib.win-amd64-3.7\_pycms.cp37-win_amd64.pyd _pycms.pyd


c:\Python37\python.exe -m pycms_test
:run
c:\Python37\python.exe %ARG% -m pycms
