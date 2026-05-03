@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if not exist bin mkdir bin
if not exist obj mkdir obj
cl /nologo /std:c++20 /EHsc /W4 /MT /O2 /DNDEBUG /Foobj\load_library_injector.obj /Fe:bin\load_library_injector.exe tools\load_library_injector.cpp advapi32.lib
