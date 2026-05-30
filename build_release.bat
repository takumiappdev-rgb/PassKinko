@echo off
setlocal

REM ============================================================
REM PassKinko Release Build Script
REM Version: V001.000.000
REM Output : RELEASE\PassKinko_V001.000.000
REM ============================================================

cd /d "%~dp0"

set "APP_NAME=PassKinko"
set "DISPLAY_NAME=パス金庫"
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

REM ------------------------------------------------------------
REM Check project
REM ------------------------------------------------------------
if not exist "%PROJECT_FILE%" (
    echo [ERROR] Project file not found.
    echo [ERROR] %PROJECT_FILE%
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Clean work folder
REM ------------------------------------------------------------
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

mkdir "%PUBLISH_DIR%"
if errorlevel 1 (
    echo [ERROR] Failed to create publish work folder.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Restore
REM ------------------------------------------------------------
echo.
echo [2/5] Restoring project...

dotnet restore "%PROJECT_FILE%"
if errorlevel 1 (
    echo [ERROR] dotnet restore failed.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Publish
REM Framework-dependent publish.
REM Do not use PublishSingleFile / PublishTrimmed to avoid ILLink.
REM ------------------------------------------------------------
echo.
echo [3/5] Publishing Release...

dotnet publish "%PROJECT_FILE%" ^
  -c Release ^
  --self-contained false ^
  -p:PublishSingleFile=false ^
  -p:PublishTrimmed=false ^
  -o "%PUBLISH_DIR%"

if errorlevel 1 (
    echo [ERROR] dotnet publish failed.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Check output
REM ------------------------------------------------------------
echo.
echo [4/5] Checking publish output...

if not exist "%PUBLISH_DIR%\%DISPLAY_NAME%.exe" (
    echo [ERROR] Release EXE was not created.
    echo [ERROR] Expected:
    echo [ERROR] %PUBLISH_DIR%\%DISPLAY_NAME%.exe
    echo.
    echo [INFO] Current publish folder:
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

if not exist "%PUBLISH_DIR%\%DISPLAY_NAME%.dll" (
    echo [ERROR] Release DLL was not created.
    echo [ERROR] Expected:
    echo [ERROR] %PUBLISH_DIR%\%DISPLAY_NAME%.dll
    echo.
    echo [INFO] Current publish folder:
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

if not exist "%PUBLISH_DIR%\%DISPLAY_NAME%.runtimeconfig.json" (
    echo [ERROR] runtimeconfig.json was not created.
    echo [ERROR] Expected:
    echo [ERROR] %PUBLISH_DIR%\%DISPLAY_NAME%.runtimeconfig.json
    echo.
    echo [INFO] Current publish folder:
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

if not exist "%PUBLISH_DIR%\%DISPLAY_NAME%.deps.json" (
    echo [ERROR] deps.json was not created.
    echo [ERROR] Expected:
    echo [ERROR] %PUBLISH_DIR%\%DISPLAY_NAME%.deps.json
    echo.
    echo [INFO] Current publish folder:
    dir "%PUBLISH_DIR%"
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Create final release folder
REM ------------------------------------------------------------
echo.
echo [5/5] Creating final release folder...

if exist "%RELEASE_DIR%" (
    rmdir /s /q "%RELEASE_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to remove existing release folder.
        echo [ERROR] Close Explorer or running app and try again.
        echo [ERROR] %RELEASE_DIR%
        pause
        exit /b 1
    )
)

mkdir "%RELEASE_DIR%"
if errorlevel 1 (
    echo [ERROR] Failed to create release folder.
    pause
    exit /b 1
)

xcopy "%PUBLISH_DIR%\*" "%RELEASE_DIR%\" /E /I /Y >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy publish files to release folder.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM Final check
REM ------------------------------------------------------------
if not exist "%RELEASE_DIR%\%DISPLAY_NAME%.exe" (
    echo [ERROR] Final EXE not found after copy.
    echo [ERROR] %RELEASE_DIR%\%DISPLAY_NAME%.exe
    pause
    exit /b 1
)

echo.
echo ============================================================
echo [SUCCESS] Release build completed.
echo.
echo Output:
echo %RELEASE_DIR%
echo.
echo Main EXE:
echo %RELEASE_DIR%\%DISPLAY_NAME%.exe
echo.
echo Note:
echo This is a framework-dependent build.
echo Target PC requires .NET 8 Desktop Runtime.
echo ============================================================
echo.

pause
exit /b 0