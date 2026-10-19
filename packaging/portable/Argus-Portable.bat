@echo off
rem ARGUS.EXE - Portable launcher
rem Runs Argus with ALL of its data (config, quarantine vault, scan
rem history) kept in the ArgusData folder beside this file, so the
rem whole folder can live on a USB stick or any folder you like.
rem Nothing is installed and nothing is written outside ArgusData.

setlocal
set "HERE=%~dp0"
set "ARGUS_DATA_DIR=%HERE%ArgusData"
if not exist "%ARGUS_DATA_DIR%" mkdir "%ARGUS_DATA_DIR%"

start "" "%HERE%Argus.exe"
endlocal
