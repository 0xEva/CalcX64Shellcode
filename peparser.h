#pragma once
#include "ntdll.h"

#define SIZE_OF_HEADERS(pFileData) \
    ((IMAGE_NT_HEADERS*)((unsigned char*)pFileData + ((IMAGE_DOS_HEADER*)pFileData)->e_lfanew))->OptionalHeader.SizeOfHeaders


#define SIZE_OF_IMAGE(pFileData) \
    (((IMAGE_NT_HEADERS*)((unsigned char*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew))->OptionalHeader.SizeOfImage)


#define NUMBER_OF_SECTIONS(pFileData) \
    (((IMAGE_NT_HEADERS*)((unsigned char*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew))->FileHeader.NumberOfSections)


#define SECTION_HEADER_AT(pFileData, index) \
    ((IMAGE_SECTION_HEADER*)((unsigned char*)IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)((unsigned char*)pFileData + ((IMAGE_DOS_HEADER*)pFileData)->e_lfanew))) + index)


#define RELOC_DIRECTORY(pFileData) \
    ((IMAGE_DATA_DIRECTORY*) &( \
        ((IMAGE_NT_HEADERS*) ( \
            (BYTE*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew \
        ))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] \
    ))


#define IMAGE_BASE(pFileData) \
    (((IMAGE_NT_HEADERS*)((BYTE*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew))->OptionalHeader.ImageBase)


#define ENTRY_IMPORT_DIRECTORY(pFileData) \
    ((IMAGE_DATA_DIRECTORY*) &( \
        ((IMAGE_NT_HEADERS*) ( \
            (BYTE*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew \
        ))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] \
    ))


#define ADDRESS_OF_ENTRY_POINT(pFileData) (\
    ((PIMAGE_NT_HEADERS)((BYTE *)(pFileData) + \
    ((PIMAGE_DOS_HEADER)(pFileData))->e_lfanew))->OptionalHeader.AddressOfEntryPoint \
)

#define EXPORT_DIRECTORY(pFileData) \
    ((IMAGE_DATA_DIRECTORY*) &( \
        ((IMAGE_NT_HEADERS*) ( \
            (BYTE*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew \
        ))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] \
    ))

#define TLS_DIRECTORY(pFileData) \
    ((IMAGE_DATA_DIRECTORY*) &( \
        ((IMAGE_NT_HEADERS*) ( \
            (BYTE*)(pFileData) + ((IMAGE_DOS_HEADER*)(pFileData))->e_lfanew \
        ))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] \
    ))
