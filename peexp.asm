.386
.model flat, stdcall
option casemap :none

include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib

.data
consoleTitle BYTE "PEExplorer",0
titleMessage BYTE "Portable Executable Explorer",13,10, 0
pathMessage BYTE "Path to your PE file:",13,10, 0

fileOpenError BYTE  "Can't open file",0


fileHandle db ?

pathBuff db 100 dup(?)

.code 
main:

invoke SetConsoleTitle, addr consoleTitle

invoke StdOut, offset titleMessage
invoke StdOut, offset pathMessage
invoke StdIn, offset pathBuff, 100

invoke 
    CreateFile,
    GENERIC_READ,
    DO_NOT_SHARE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    0

mov fileHandle,eax

cmp fileHandle,INVALID_HANDLE_VALUE
jz fileOpenError



fileOpenError:
invoke StdOut,fileOpenError


invoke ExitProcess, 0
end main