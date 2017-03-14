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
machineMessageTitle BYTE "Machine:",0
endMachineMessageTitle BYTE " type",13,10,0
numberOfSectionTitle BYTE "Number of sections:",0


fileOpenSuccessMessege BYTE  "File was opended!",13,10,0
errorWhileReadingMessege BYTE  "Error while reading",13,10,0
fileOpenErrorMessege BYTE  "Can't open file",0
fileSizeErrorMessege BYTE  "Can't determinate file size",0
fileHaveNotDosHeaderErrorMessege BYTE  "It hasn't DOS title!",0
fileIsNotPEErrorMessege BYTE  "it's not PE file",0
PEMessege BYTE  "it is PE file",13,10, 0

debugMessege BYTE  "DEBUG",0



fileSizeIsMessege BYTE  "File size is:",0
bytesMessege BYTE " bytes",13,10,0

FileName db "C:\Users\Vadimcg\Desktop\MASMProjects\ff.exe",NULL
fileHandle DWORD  ?

buff BYTE 100 dup(?)
;Variable will store amout of read bytes
readInfo dd ?

adreessVal dd ?

;Variable for writing date 
dateTimeVal BYTE 16 dup(?)

.code 


main:


invoke SetConsoleTitle, addr consoleTitle

clearBuffer PROTO
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
invoke dwtoa,offset readInfo,offset buff
invoke StdOut, offset buff
invoke StdOut, offset bytesMessege
xor eax,eax
mov readInfo,eax
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
mov adreessVal,eax

;reading PE title
invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,addr buff,4,addr readInfo,0

 
 ;Checking PE title
mov al,buff
cmp al,50h

;if it is not PE!
jnz notPEFileError

mov al,buff+1
cmp al,45h

;if it is not PE!
jnz notPEFileError


;if it is PE 
invoke StdOut, offset PEMessege


;Reading of IMAGE_FILE_HEADER 20bytes after signature


;Machine
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,2,addr readInfo,0
invoke StdOut, offset machineMessageTitle
invoke StdOut, offset buff
invoke StdOut, offset endMachineMessageTitle

;NumberOfSections
mov eax,adreessVal
add eax,2
mov adreessVal,eax

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,2,addr readInfo,0
invoke StdOut, offset numberOfSectionTitle
xor eax,eax
mov ax,WORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff


;TimeDateStamp
mov eax,adreessVal
add eax,2
mov adreessVal,eax

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0



;---------------------------------END READING------------------------------


jmp closeFile

fileOpenError:
invoke StdOut,offset fileOpenErrorMessege
jmp endPE

readingError:
invoke StdOut,offset errorWhileReadingMessege
jmp closeFile

notExeFileError:
invoke StdOut,offset fileHaveNotDosHeaderErrorMessege
jmp closeFile

notPEFileError:
invoke StdOut,offset fileIsNotPEErrorMessege
jmp closeFile

fileSizeError:
invoke StdOut,offset fileSizeErrorMessege

closeFile:
invoke CloseHandle,offset fileHandle
jmp endPE



endPE:
invoke ExitProcess, 0

;Function clear buffer
clearBuffer PROC
    invoke StdOut,OFFSET debugMessege
    ret
clearBuffer ENDP

end main




