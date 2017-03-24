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
timeDateStampTitle BYTE "TimeDateStamp:",0
pointerToSymbolTableTitle BYTE "PointerToSymbolTable:",0	
numberOfSymbolsTitle BYTE "NumberOfSymbols:",0
sizeOfOptionalHeaderTitle BYTE "SizeOfOptionalHeader:",0
characteristicsTitle BYTE "Characteristics:",0

;Magic constants
magicTitle BYTE "Magic:",0
pe32 BYTE "PE32",13,10,0
pe64 BYTE "PE64",13,10,0

sizeOfCode BYTE "SizeOfCode:"
sizeOfInitializedData BYTE "SizeOfInitializedData:",0
sizeOfUninitializedData BYTE "SizeOfUninitializedData:",0

entryPoint BYTE "EtryPoint:",0
baseOfCode BYTE "BaseOfCode:",0
baseOfData BYTE "BaseOfData:",0
imageBase BYTE "ImageBase:",0

sectionAlignment BYTE "SectionAlignment:",0
fileAlignment BYTE "FileAlignment:",0
majorOperatingSystemVersion BYTE "MajorOperatingSystemVersion:",0
minorOperatingSystemVersion BYTE "MinorOperatingSystemVersion:",0
sizeOfImage BYTE "SizeOfImage:",0
sizeOfHeaders BYTE "SizeOfHeaders:",0
checkSum BYTE "CheckSum:",0
subsystem BYTE "Subsystem:",0 
 

dotACSII BYTE 2Eh,0
nLine BYTE 13,10,0



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
;10 PE and 20 PE+
peType BYTE ?
fileHandle DWORD  ?

helperVal DWORD ?

buff BYTE 100 dup(?)
numberBuff BYTE 7 dup(?)

;Variable will store amout of read bytes
readInfo DWORD ?

adreessVal DWORD ?

;Variable for writing date 
dateTimeVal BYTE 16 dup(?)

.code 


main:


invoke SetConsoleTitle, addr consoleTitle

dateFromSeconds PROTO,milsec:DWORD
debugShowNumber PROTO,number:DWORD

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
invoke dwtoa,readInfo,offset buff
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


mov ah,10
mov al,13

mov readInfo,eax
invoke StdOut, offset readInfo

;TimeDateStamp
mov eax,adreessVal
add eax,2
mov adreessVal,eax



invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

invoke StdOut, offset timeDateStampTitle

invoke dateFromSeconds,DWORD PTR buff 
invoke StdOut,offset nLine

;PointerToSymbolTable	
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset pointerToSymbolTableTitle

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

xor eax,eax
mov ax,WORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine


;NumberOfSymbols	
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset numberOfSymbolsTitle

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;SizeOfOptionalHeader
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset sizeOfOptionalHeaderTitle

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,2,addr readInfo,0

xor eax,eax
mov ax,WORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;Characteristics
mov eax,adreessVal
add eax,2
mov adreessVal,eax

invoke StdOut, offset characteristicsTitle

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,2,addr readInfo,0

xor eax,eax
mov ax,WORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine



;Magic
mov eax,adreessVal
add eax,2
mov adreessVal,eax

invoke StdOut, offset magicTitle

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,2,addr readInfo,0

xor eax,eax
mov ax,WORD PTR buff

cmp ax,10Bh
jz showPE32

cmp ax,20Bh
jz showPE64

showPE32:
invoke StdOut, offset pe32
mov al,10
mov peType,al

jmp afterMagic

showPE64:
invoke StdOut, offset pe32
mov al,20
mov peType,al
jmp afterMagic

afterMagic:

;SizeOfCode
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset sizeOfCode

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine


;SizeOfInitializedData
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset sizeOfInitializedData

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;SizeOfUninitializedData
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset sizeOfUninitializedData

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;EntryPoint
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset entryPoint

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine


;BaseOfCode(hex)
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset baseOfCode

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;BaseOfData(hex)
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset baseOfData

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0

mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

invoke StdOut,offset nLine

;ImageBase(hex)
mov eax,adreessVal
add eax,4
mov adreessVal,eax

invoke StdOut, offset imageBase

invoke SetFilePointer,fileHandle,adreessVal,0,FILE_BEGIN

cmp peType,10
jz pe32ImageBase

pe32ImageBase:

; For PE 32 format
invoke ReadFile,fileHandle,offset buff,4,addr readInfo,0
mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

mov eax,adreessVal
add eax,4
mov adreessVal,eax

jmp afterImageBase

; For PE 64 format
invoke ReadFile,fileHandle,offset buff,8,addr readInfo,0
mov eax,DWORD PTR buff
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

mov eax,DWORD PTR buff+4
invoke dwtoa,eax,offset buff
invoke StdOut, offset buff

mov eax,adreessVal
add eax,8
mov adreessVal,eax

jmp afterImageBase




afterImageBase:
invoke StdOut,offset nLine


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

;Function showing date
dateFromSeconds PROC, milsec:DWORD

    ;Getting year
    xor edx,edx    
    mov eax,milsec

    ; 31556926-sec in one year
    mov ebx,1E1853Eh
    ;1470103413/31556926=46
    div  ebx
    

    mov helperVal,edx
    
    ;UNIX time from 01.01.1970
    add eax,1970
    invoke dwtoa,eax,offset numberBuff
    invoke StdOut,offset numberBuff 


    invoke StdOut,offset dotACSII
    ;Getting month
    
    mov eax,helperVal
    xor edx,edx
    ;2592000-sec in one month
    mov ebx,278D00h
    div  ebx
    mov helperVal,edx
    ;UNIX time from 01.01.1970
    add eax,1
    invoke dwtoa,eax,offset readInfo
    invoke StdOut,offset readInfo

    invoke StdOut,offset dotACSII
    ;Getting day
    mov eax,helperVal
    xor edx,edx
    ;86400-sec in one day
    mov ebx,549888
    div  ebx
    mov helperVal,edx
    ;UNIX time from 01.01.1970
    add eax,1
    invoke dwtoa,eax,offset readInfo
    invoke StdOut,offset readInfo

    ret
dateFromSeconds ENDP

;Function showing number
debugShowNumber PROC, number:DWORD

        invoke StdOut,offset nLine


        invoke dwtoa,number,offset helperVal
        invoke StdOut,offset helperVal

        invoke StdOut,offset nLine

       ret

debugShowNumber ENDP

end main




