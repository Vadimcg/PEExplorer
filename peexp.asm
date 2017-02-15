.386
.model flat, stdcall
option casemap :none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib
include \masm32\include\user32.inc 
includelib \masm32\lib\user32.lib

 
.data
consoleTitle BYTE "PEExplorer",0
titleMessage BYTE "Portable Executable Explorer",13,10, 0
pathMessage BYTE "Path to your PE file:",13,10, 0

fileOpenSuccessMessege BYTE  "File was opended!",13,10,0
fileOpenErrorMessege BYTE  "Can't open file",0

FileName db "C:\Users\Vadimcg\Desktop\MASMProjects\test.txt",NULL
fileHandle HANDLE  ?

pathBuff db 100 dup(?)

.code 
main:

invoke SetConsoleTitle, addr consoleTitle

invoke StdOut, offset titleMessage
invoke StdOut, offset pathMessage
invoke StdIn, offset pathBuff, 100

invoke  CreateFile,addr pathBuff, GENERIC_READ, FILE_SHARE_READ OR FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL

mov fileHandle,eax
cmp fileHandle,INVALID_HANDLE_VALUE
jz fileOpenError


invoke StdOut,offset fileOpenSuccessMessege
jmp endPE

fileOpenError:
invoke StdOut,offset fileOpenErrorMessege

endPE:
invoke ExitProcess, 0

end main