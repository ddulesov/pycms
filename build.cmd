setlocal
set ACTION=%1
set ARG=%2

if "%ACTION%"=="run"  (
	set ARG="-i" 
	goto:run 
)
if "%ACTION%"=="test"  (
	set ARG="-i" 
	goto:test 
)

del _pycms.pyd

c:\Python37\python.exe setup.py  build
IF ERRORLEVEL 1 GOTO:eof
  
copy build\lib.win-amd64-3.7\_pycms.cp37-win_amd64.pyd _pycms.pyd

goto:run


:test
c:\Python37\python.exe -m pycms_test
goto:eof

:run
c:\Python37\python.exe %ARG% -m pycms
goto:eof