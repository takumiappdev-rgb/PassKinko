@echo off
setlocal
set "ROOT=%~dp0"
set "PROJECT=%ROOT%PassKinko.App\PassKinko.App.csproj"

echo Starting development run...
dotnet restore "%PROJECT%"
if errorlevel 1 (
  echo Restore failed.
  pause
  exit /b 1
)

dotnet run --project "%PROJECT%"
pause
