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
fileSizeErrorMessege BYTE  "Can't determinate file size",0
fileIsNotEXEErrorMessege BYTE  "It isn't exe file!",0
debugMessege BYTE  "DEBUG",0



fileSizeIsMessege BYTE  "File size is:",0
bytesMessege BYTE " bytes",13,10,0

FileName db "C:\Users\Vadimcg\Desktop\MASMProjects\ff.exe",NULL
fileHandle DWORD  ?

buff WORD 100 dup(?)
;Variable will store amout of read bytes
readInfo dd ?

adreessVal dd ?

.code 

;Function clear buffer
clearBuffer PROC
    invoke StdOut,OFFSET debugMessege
    ret
clearBuffer ENDP
main:

invoke SetConsoleTitle, addr consoleTitle


call clearBuffer

invoke StdOut, offset titleMessage
invoke StdOut, offset pathMessage
invoke StdIn, offset buff, 100



xor eax,eax
;Try to open file
invoke  CreateFile,addr FileName, GENERIC_READ,FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
;Cheecking resault
mov fileHandle,eax    

cmp fileHandle,INVALID_HANDLE_VALUE
jz fileOpenError

;File was opend successfully ! -messege
invoke StdOut,offset fileOpenSuccessMessege

;--------------------------------GETTING SIZE------------------------------
invoke GetFileSize,fileHandle, NULL
mov readInfo,eax

cmp readInfo,INVALID_FILE_SIZE
jz fileSizeError

;Show information about size
invoke StdOut, offset fileSizeIsMessege
invoke StdOut, offset readInfo
invoke StdOut, offset bytesMessege
;-------------------------------END----------------------------------------


;---------------------------------READING----------------------------------
mov readInfo,0
;Read IMAGE_DOS_SIGNATURE it must be "MZ" for exe files OFFSET 0  SIZE WORD
invoke ReadFile,fileHandle,addr buff,2,addr readInfo,0
cmp readInfo,2
jnz readingError




;Cheecking on DOS format
mov esi,offset buff

mov al,[esi]
cmp al, 4Dh
jnz notExeFileError

mov al,[esi+1]
cmp al,5Ah
jnz notExeFileError

;mov cursore to e_lfanew
invoke SetFilePointer,fileHandle,3Ch,0,FILE_BEGIN
;reading e_lfanew 
invoke ReadFile,fileHandle,addr buff,4,addr readInfo,0

mov eax,DWORD PTR buff

INVOKE  dw2hex,eax,OFFSET adreessVal
mov eax,adreessVal

invoke StdOut,OFFSET adreessVal

;reading PE title
invoke SetFilePointer,fileHandle,00000100h,0,FILE_BEGIN
invoke ReadFile,fileHandle,addr buff,4,addr readInfo,0
mov  eax,DWORD PTR buff

invoke StdOut,OFFSET buff

;---------------------------------END READING------------------------------


jmp closeFile

fileOpenError:
invoke StdOut,offset fileOpenErrorMessege
jmp endPE

readingError:
invoke StdOut,offset errorWhileReadingMessege
jmp closeFile

notExeFileError:
invoke StdOut,offset fileIsNotEXEErrorMessege
jmp closeFile

fileSizeError:
invoke StdOut,offset fileSizeErrorMessege

closeFile:
invoke CloseHandle,offset fileHandle
jmp endPE



endPE:
invoke ExitProcess, 0

end main




