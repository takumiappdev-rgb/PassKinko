@echo off
setlocal
set "DATA=%LOCALAPPDATA%\PassKinko"

echo This will delete local PassKinko data.
echo Target: %DATA%
choice /m "Continue"
if errorlevel 2 exit /b 0
if exist "%DATA%" rmdir /s /q "%DATA%"
echo Done.
pause
