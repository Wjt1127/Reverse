#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>


//函数计算导出／导入表相对内存的偏移量
DWORD RVA2Offset(PIMAGE_NT_HEADERS pNTHeader, DWORD dwExpotRVA)  //输入PE头地址 对应表的RVA
{
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNTHeader + sizeof(IMAGE_NT_HEADERS));//获取节表或者段表

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)  //对PE文件的每个块进行判断
    {   //获取该节大小
        if (dwExpotRVA >= pSection[i].VirtualAddress && dwExpotRVA < (pSection[i].VirtualAddress + pSection[i].SizeOfRawData))
        {
            return pSection[i].PointerToRawData + (dwExpotRVA - pSection[i].VirtualAddress);
        }
    }

    return 0;
}


int main(int argc, char* argv[])
{
    char szExePath[MAX_PATH]; //声明文件名
    //"C:\\Program Files (x86)\\Application Verifier\\vrfauto.dll"
    printf("Please input the execution file path:\n");
    scanf("%s", szExePath);
    HANDLE hFile = CreateFileA(szExePath, GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL); //获得PE文件句柄
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL); //创建一个新的文件映射内核对象
    //将一个文件映射对象映射到内存,得到指向映射到内存的第一个字节的指针pbFile
    PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (INVALID_HANDLE_VALUE == hFile || NULL == hMapping || NULL == pbFile)
    {
        printf("\n\t---------- The File Inexistence! ----------\n");
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }
    printf("<------------------------PE Header----------------------->\n");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbFile;//pDosHeader指向DOS头起始位置
    printf("PE Header e_lfanew：0x%x\n", pDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);//计算PE头位置

    if (0x00004550 != pNTHeader->Signature)
    {
        printf("\n\t---------- Lawless PE File! ----------\n");
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }
    printf("<----------------------FileHeader---------------------->\n");
    WORD wNumberOfSections = (WORD)pNTHeader->FileHeader.NumberOfSections;//找到存放节数的项，并打印
    printf("NumberOfSections: %d\n", wNumberOfSections);

    WORD wSizeOfOptionalHeader = (WORD)pNTHeader->FileHeader.SizeOfOptionalHeader;//找到可选头长度，并打印
    printf("SizeOfOptionalHeader: %d\n", wSizeOfOptionalHeader);

    //可选映像头
    printf("<--------------------Optional Header-------------------->\n");
    DWORD dwSizeOfCode = (DWORD)pNTHeader->OptionalHeader.SizeOfCode;
    printf("SizeOfCode: 0x%08X\n", dwSizeOfCode);

    DWORD dwAddressOfEntryPoint = (DWORD)pNTHeader->OptionalHeader.AddressOfEntryPoint;
    printf("AddressOfEntryPoint: 0x%08X\n", dwAddressOfEntryPoint);

    DWORD dwImageBase = (DWORD)pNTHeader->OptionalHeader.ImageBase;
    printf("ImageBase: 0x%08X\n", dwImageBase);

    DWORD dwSectionAlignment = (DWORD)pNTHeader->OptionalHeader.SectionAlignment;
    printf("SectionAlignment: 0x%08X\n", dwSectionAlignment);

    DWORD dwFileAlignment = (DWORD)pNTHeader->OptionalHeader.FileAlignment;
    printf("FileAlignment: 0x%08X\n", dwFileAlignment);

    DWORD dwSizeOfImage = (DWORD)pNTHeader->OptionalHeader.SizeOfImage;
    printf("SizeOfImage: 0x%08X\n", dwSizeOfImage);

    DWORD dwNumberOfRvaAndSize = (DWORD)pNTHeader->OptionalHeader.NumberOfRvaAndSizes;
    printf("NumberOfRvaAndSizes: 0x%08X\n", dwNumberOfRvaAndSize);

    DWORD dwSectionHeaderOffset = (DWORD)pNTHeader + 24 + (DWORD)wSizeOfOptionalHeader;//计算节表的位置

    printf("<----------------------SectionTable---------------------->\n");
    int NumOfSec = 0;
    for (NumOfSec; NumOfSec < wNumberOfSections; NumOfSec++)
    {
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(dwSectionHeaderOffset + 40 * NumOfSec);
        printf("%d 's Name):%s\n", NumOfSec + 1, pSectionHeader->Name);
        DWORD dwVirtualAddress = (DWORD)pSectionHeader->VirtualAddress;
        printf("VirtualAddress: 0x%08X\n", dwVirtualAddress);
        DWORD dwSizeOfRawData = (DWORD)pSectionHeader->SizeOfRawData;
        printf("SizeOfRawData: 0x%08X\n", dwSizeOfRawData);
        DWORD dwPointerToRawData = (DWORD)pSectionHeader->PointerToRawData;
        printf("PointerToRawData: 0x%08X\n", dwPointerToRawData);
    }

    printf("<--------------------Export Table-------------------->\n");

    DWORD dwExportOffset = RVA2Offset(pNTHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pbFile + dwExportOffset);
    DWORD dwFunctionNameOffset = (DWORD)pbFile + RVA2Offset(pNTHeader, pExport->Name);
    DWORD* pdwNamesAddress = (DWORD*)((DWORD)pbFile + RVA2Offset(pNTHeader, pExport->AddressOfNames));
    DWORD* pdwFunctionAddress = (DWORD*)((DWORD)pbFile + RVA2Offset(pNTHeader, pExport->AddressOfFunctions));
    WORD* pwOrdinals = (WORD*)((DWORD)pbFile + RVA2Offset(pNTHeader, pExport->AddressOfNameOrdinals));

    printf("AddressOfNameOrdinals: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfNameOrdinals));
    printf("AddressOfFunctions: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfFunctions));
    printf("AddressOfNames: 0x%08X\n", RVA2Offset(pNTHeader, pExport->AddressOfNames));
    if (0 == pExport->NumberOfFunctions)
    {
        printf("\n\t---------- No Export Tabel! ----------\n");
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }

    printf("FileName: %s\n", dwFunctionNameOffset);
    printf("NumberOfFunctions: %d\n", pExport->NumberOfFunctions);
    printf("NumberOfNames: %d\n\n", pExport->NumberOfNames);
    printf("============NameExport:\n\n");

    int IsFound[1000] = { 0 };
    int k;
    for (k = 0; k < pExport->NumberOfFunctions; k++)
    {
        IsFound[k] = 0;
        //printf("%d ",IsFound[k]);
    }
    int i;
    for (i = 0; i < pExport->NumberOfNames; i++)
    {
        DWORD dwFunctionAddress = pdwFunctionAddress[pwOrdinals[i]];
        DWORD pdwFunNameOffset = (DWORD)pbFile + RVA2Offset(pNTHeader, pdwNamesAddress[i]);
        IsFound[pwOrdinals[i]] = 1;
        printf("[ExportNum]: %-4d  [Name]: %-30s [RVA]: 0x%08X\n", pExport->Base + pwOrdinals[i], pdwFunNameOffset, dwFunctionAddress);
    }

    printf("\n============NumberExport:\n");

    int m;
    for (m = 0; m < pExport->NumberOfFunctions; m++)
    {
        if (IsFound[m] != 1)
        {
            DWORD dwFunctionAddress = pdwFunctionAddress[m];
            printf("[ExportNum]: %-4d [RVA]: 0x%08X\n", pExport->Base + m, dwFunctionAddress);
        }
    }

    printf("\n");

    printf("<--------------------Inport Table-------------------->\n");
    int cont = 0;
    do {
        DWORD dwInportOffset = RVA2Offset(pNTHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        dwInportOffset = dwInportOffset + cont;
        PIMAGE_IMPORT_DESCRIPTOR  pInport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pbFile + dwInportOffset);
        if (pInport->OriginalFirstThunk == 0 && pInport->TimeDateStamp == 0 && pInport->ForwarderChain == 0 && pInport->Name == 0 && pInport->FirstThunk == 0)
            break;
        DWORD dwOriginalFirstThunk = (DWORD)pbFile + RVA2Offset(pNTHeader, pInport->OriginalFirstThunk);//VA to IAT
        DWORD dwFirstThunk = (DWORD)pbFile + RVA2Offset(pNTHeader, pInport->FirstThunk);//VA to IAT
        DWORD dwName = (DWORD)pbFile + RVA2Offset(pNTHeader, pInport->Name);
        printf("\n---------Inport File Name: %s\n\n", dwName);

        if (dwOriginalFirstThunk == 0x00000000)
        {
            dwOriginalFirstThunk = dwFirstThunk;
        }
        DWORD* pdwTrunkData = (DWORD*)dwOriginalFirstThunk;
        int n = 0, x = 0;
        while (pdwTrunkData[n] != 0)
        {
            DWORD TrunkData = pdwTrunkData[n];
            if (TrunkData < IMAGE_ORDINAL_FLAG32)//名字导入
            {
                PIMAGE_IMPORT_BY_NAME pInportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbFile + RVA2Offset(pNTHeader, TrunkData));
                printf("-----------InportByName: %s\n", pInportByName->Name);
            }
            else//序号导入
            {
                DWORD FunNumber = (DWORD)(TrunkData - IMAGE_ORDINAL_FLAG32);
                printf("-----------InportByNumber: %-4d ", FunNumber);
            }
            if (x != 0 && x % 3 == 0) printf("\n");
            n++;
            x++;
        }
        cont = cont + 40;
    } while (true);
    if (NULL != pbFile)
    {
        UnmapViewOfFile(pbFile);
    }

    if (NULL != hMapping)
    {
        CloseHandle(hMapping);
    }

    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }
    return 0;
}
