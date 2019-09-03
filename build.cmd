setlocal
@echo off
set ACTION=%1
set ARG=%2

if "%ACTION%"=="run"  (
	set ARG="-i" 
	goto:run 
)
if "%ACTION%"=="test"  (
	goto:test 
)

if "%ACTION%"=="dist"  (
	goto:dist 
)

rem del _pycms.pyd

python.exe setup.py  build
IF ERRORLEVEL 1 GOTO:eof
  
rem copy build\lib.win-amd64-3.7\_pycms.cp37-win_amd64.pyd _pycms.pyd

if "%ACTION%"=="build"   goto:eof 

call:run

:test
python.exe -m pycms_test
goto:eof

:run
python.exe %ARG% -m pycms_run
goto:eof

:dist
python.exe setup.py  build
python.exe setup.py  install

goto:eof