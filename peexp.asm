.386
.model flat, stdcall
option casemap :none

include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib

.data
consoleTitle BYTE "PEExplorer",0
titleMessage db "Portable Executable Explorer",13,10, 0
pathMessage db "Path to your PE file:",13,10, 0

pathBuff db 100 dup(?)

.code 
main:

invoke SetConsoleTitle, addr consoleTitle

invoke StdOut, offset titleMessage
invoke StdOut, offset pathMessage
invoke StdIn, offset pathBuff, 100





invoke ExitProcess, 0
end main