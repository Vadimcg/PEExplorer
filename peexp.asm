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
errorWhileReadingMessege BYTE  "Error while reading",13,10,0
fileOpenErrorMessege BYTE  "Can't open file",0

FileName db "C:\Users\Vadimcg\Desktop\MASMProjects\test.txt",NULL
fileHandle HANDLE  ?

testValue db 9

buff db 100 dup(?)
;Variable will store amout of read bytes
readInfo WORD 0

.code 
main:

mov eax,offset testValue

invoke SetConsoleTitle, addr consoleTitle

invoke StdOut, offset titleMessage
invoke StdOut, offset pathMessage
invoke StdIn, offset buff, 100

invoke  CreateFile,addr FileName, GENERIC_READ, FILE_SHARE_READ OR FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL

mov fileHandle,eax
cmp fileHandle,INVALID_HANDLE_VALUE
jz fileOpenError


invoke StdOut,offset fileOpenSuccessMessege

;Read IMAGE_DOS_SIGNATURE it must be "MZ" for exe files OFFSET 0  SIZE WORD
invoke ReadFile,addr fileHandle,addr buff,2,readInfo,0

cmp readInfo,2
jnz fileOpenError



jmp endPE

readingError:
invoke StdOut,offset errorWhileReadingMessege

fileOpenError:
invoke StdOut,offset fileOpenErrorMessege



endPE:
invoke ExitProcess, 0

end main