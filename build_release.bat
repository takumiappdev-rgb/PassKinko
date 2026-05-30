@echo off
setlocal

REM ============================================================
REM PassKinko Release Build Script
REM Version: V001.000.000
REM Output : RELEASE\PassKinko_V001.000.000
REM ============================================================

cd /d "%~dp0"

set "APP_NAME=PassKinko"
set "VERSION=V001.000.000"

set "PROJECT_DIR=%~dp0PassKinko.App"
set "PROJECT_FILE=%PROJECT_DIR%\PassKinko.App.csproj"

set "WORK_DIR=%~dp0BUILD_WORK"
set "PUBLISH_DIR=%WORK_DIR%\publish_tmp"
set "RELEASE_ROOT=%~dp0RELEASE"
set "RELEASE_DIR=%RELEASE_ROOT%\PassKinko_%VERSION%"

echo [INFO] PassKinko Release Build
echo [INFO] Version: %VERSION%
echo.

echo [1/5] Cleaning work folder...
if exist "%WORK_DIR%" (
    rmdir /s /q "%WORK_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to remove BUILD_WORK folder.
        echo [ERROR] Close Explorer or running app and try again.
        pause
        exit /b 1
    )
)

echo.
echo [2/5] Restoring project...
dotnet restore "%PROJECT_FILE%"
if errorlevel 1 (
    echo [ERROR] dotnet restore failed.
    pause
    exit /b 1
)

echo.
echo [3/5] Publishing Release...
dotnet publish "%PROJECT_FILE%" -c Release -o "%PUBLISH_DIR%" --self-contained false /p:PublishSingleFile=false
if errorlevel 1 (
    echo [ERROR] dotnet publish failed.
    pause
    exit /b 1
)

echo.
echo [4/5] Checking publish output...

dir /b "%PUBLISH_DIR%\*.exe" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Release EXE was not created.
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

dir /b "%PUBLISH_DIR%\*.dll" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Release DLL was not created.
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

dir /b "%PUBLISH_DIR%\*.runtimeconfig.json" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] runtimeconfig.json was not created.
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

dir /b "%PUBLISH_DIR%\*.deps.json" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] deps.json was not created.
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

echo.
echo [5/5] Creating release folder...
if not exist "%RELEASE_ROOT%" mkdir "%RELEASE_ROOT%"

if exist "%RELEASE_DIR%" (
    rmdir /s /q "%RELEASE_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to remove old release folder.
        pause
        exit /b 1
    )
)

mkdir "%RELEASE_DIR%"
xcopy "%PUBLISH_DIR%\*" "%RELEASE_DIR%\" /E /I /Y >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy publish files to release folder.
    pause
    exit /b 1
)

if exist "%RELEASE_DIR%\*.pdb" del /q "%RELEASE_DIR%\*.pdb"

dir /b "%RELEASE_DIR%\*.exe" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Final EXE not found after copy.
    dir "%RELEASE_DIR%"
    pause
    exit /b 1
)

echo.
echo [OK] Release build completed.
echo.
echo Output:
echo %RELEASE_DIR%
echo.
echo Main EXE:
dir /b "%RELEASE_DIR%\*.exe"
echo.
pause
exit /b 0