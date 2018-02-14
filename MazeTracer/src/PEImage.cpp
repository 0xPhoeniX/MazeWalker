#include "PEImage.h"
#include "crypto.h"
#include <algorithm>
#include <Windows.h>

//REGISTER_MATYPE(MazeWalker::PEImage);

namespace MazeWalker {

    PEImage::PEImage(int entry, int base, size_t size, const char* path) : Image(entry, base, size) { 
        _imphash = new char[33];
        _exphash = new char[33];
        _path = 0;
        _name = "";
        if (_imphash) {
            memset(_imphash, 0, 33);
        }
        if (_exphash) {
            memset(_exphash, 0, 33);
        }
        if (path) {
            _path = new char[MAX_PATH];
            memset(_path, 0, MAX_PATH);
            memcpy(_path, path, strlen(path));
            _name = strrchr(_path, '\\') + 1;
        }
    }

    PEImage::~PEImage() {
        if (_imphash) {
            delete[] _imphash; _imphash = 0;
        }

        if (_exphash) {
            delete[] _exphash; _exphash = 0;
        }

        if (_path) {
            delete[] _path; _path = 0;
        }

        _name = 0;
    }

    bool PEImage::isValid(const char* data, size_t size) {
        if (data) {
            return (data[0] == 'M' && data[1] == 'Z');
        }

        return false;
    }

    const char* PEImage::Name() const {
        return _name;
    }

    const char* PEImage::Path() const {
        return _path;
    }

    const char* PEImage::ImpHash() const {
        PIMAGE_DOS_HEADER doshdr;
        PIMAGE_NT_HEADERS nthdr;
        PIMAGE_NT_HEADERS32 nthdr32;
        PIMAGE_NT_HEADERS64 nthdr64;
        PIMAGE_IMPORT_DESCRIPTOR importDir = NULL;
        PIMAGE_THUNK_DATA pimage_thunk_data;
        PIMAGE_THUNK_DATA64 pimage_thunk_data64;
        std::string dllname;
        PCHAR       pHintName;
        std::string pAPIName;
        std::string imphashdata;
        size_t size = 0;
        const char* data = getLatestState(size);
    
        if (data)
        {
            doshdr = (PIMAGE_DOS_HEADER)data;

            if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
                goto error;

            nthdr = (PIMAGE_NT_HEADERS)(data + doshdr->e_lfanew);
            if (nthdr->Signature != IMAGE_NT_SIGNATURE)
                goto error;

            if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
                importDir = (PIMAGE_IMPORT_DESCRIPTOR)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + data);
            }
            else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
                importDir = (PIMAGE_IMPORT_DESCRIPTOR)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + data);
            }

            if ((char*)importDir == data)
                goto error;

            while (importDir->Name) {
                if (strlen((PSTR)(importDir->Name + data))) {
                    dllname = std::string((PSTR)(importDir->Name + data));
                    std::transform(dllname.begin(), dllname.end(), dllname.begin(), tolower);
                    dllname.erase(dllname.length() - 4, 4);

                    if(importDir->OriginalFirstThunk!=0) {
                        pHintName = (PCHAR)(data + importDir->OriginalFirstThunk);
                    }
                    else {
                        pHintName = (PCHAR)(data + importDir->FirstThunk);
                    }

                    if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                        pimage_thunk_data = (PIMAGE_THUNK_DATA) pHintName;
                        while(pimage_thunk_data && pimage_thunk_data->u1.AddressOfData != 0)
                        {
                            DWORD dwAPIaddress;

                            dwAPIaddress = pimage_thunk_data->u1.AddressOfData;

                            if((pimage_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG) == IMAGE_ORDINAL_FLAG)
                            {
                                std::ostringstream ss;

                                dwAPIaddress&= 0x7FFFFFFF;
                                ss << dwAPIaddress;
                                imphashdata.append(dllname);
                                imphashdata.append(".");
                                imphashdata.append("ord");
                                imphashdata.append(ss.str());
                                imphashdata.append(",");
                            }
                            else
                            {
                                pAPIName = std::string(data +  dwAPIaddress + 2);
                                std::transform(pAPIName.begin(), pAPIName.end(), pAPIName.begin(), tolower);
                                imphashdata.append(dllname);
                                imphashdata.append(".");
                                imphashdata.append(pAPIName);
                                imphashdata.append(",");
                            }

                            pimage_thunk_data++;
                        }
                    }
                    else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                        pimage_thunk_data64 = (PIMAGE_THUNK_DATA64) pHintName;
                        while(pimage_thunk_data64 && pimage_thunk_data64->u1.AddressOfData != 0)
                        {
                            ULONGLONG dwAPIaddress;

                            dwAPIaddress = pimage_thunk_data64->u1.AddressOfData;

                            if((pimage_thunk_data64->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == IMAGE_ORDINAL_FLAG64)
                            {
                                std::ostringstream ss;
                                dwAPIaddress&= 0x7FFFFFFFFFFFFFFF;
                                ss << dwAPIaddress;
                                imphashdata.append(dllname);
                                imphashdata.append(".");
                                imphashdata.append("ord");
                                imphashdata.append(ss.str());
                                imphashdata.append(",");
                            }
                            else
                            {
                                pAPIName = std::string(data +  dwAPIaddress + 2);
                                std::transform(pAPIName.begin(), pAPIName.end(), pAPIName.begin(), tolower);
                                imphashdata.append(dllname);
                                imphashdata.append(".");
                                imphashdata.append(pAPIName);
                                imphashdata.append(",");
                            }

                            pimage_thunk_data64++;
                        }
                    }
                }

                importDir++;
            }
        
            if (imphashdata.length())
            {
                imphashdata.erase(imphashdata.length() - 1, 1);
                if (calc_buf_md5(imphashdata.c_str(), imphashdata.length(), _imphash))
                    goto error;

                return _imphash;
            }
        }

    error:
        return "";
    }

    const char* PEImage::ExpHash() const {
        PIMAGE_DOS_HEADER doshdr;
        PIMAGE_NT_HEADERS nthdr;
        PIMAGE_NT_HEADERS32 nthdr32;
        PIMAGE_NT_HEADERS64 nthdr64;
        PIMAGE_EXPORT_DIRECTORY exportDir = NULL; 
        PDWORD functions = NULL;
        PWORD ordinals = NULL;
        PDWORD name = NULL;
        std::string exphashdata;
        size_t size = 0;
        const char* data = getLatestState(size);
    
        if (data)
        {
            doshdr = (PIMAGE_DOS_HEADER)data;

            if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
                goto error;    

            nthdr = (PIMAGE_NT_HEADERS)(data + doshdr->e_lfanew);
            if (nthdr->Signature != IMAGE_NT_SIGNATURE)
                goto error;

            if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
                exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + data);
            }
            else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
                exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + data);
            }

            if (exportDir && (char*)exportDir != data)
            {
                functions = (PDWORD)(exportDir->AddressOfFunctions + data);
                ordinals = (PWORD)(exportDir->AddressOfNameOrdinals + data);
                name = (PDWORD)(exportDir->AddressOfNames + data);

                for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++ )
                {
                    for (DWORD j = 0; j < exportDir->NumberOfNames; j++ )
                        if ( ordinals[j] == i )
                        {
                            exphashdata.append(std::string((char*)(name[j] + data)));
                            exphashdata.append(",");
                            break;
                        }
                }

                if (exphashdata.length())
                {
                    exphashdata.erase(exphashdata.length() - 1, 1);
                    if (calc_buf_md5(exphashdata.c_str(), exphashdata.length(), _exphash))
                        goto error;
                }
            }

            return _exphash;
        }

    error:
        return "";
    }

    const char* PEImage::Resolve(int address) const {
        PIMAGE_DOS_HEADER doshdr;
        PIMAGE_NT_HEADERS nthdr;
        PIMAGE_NT_HEADERS32 nthdr32;
        PIMAGE_NT_HEADERS64 nthdr64;
        PIMAGE_EXPORT_DIRECTORY exportDir; 
        DWORD i, image_size = 0;
        PDWORD functions = NULL;
        PWORD ordinals = NULL;
        PDWORD names = NULL;
        size_t size = 0;
        const char* data = getLatestState(size);

    
        if (data == NULL)
            return 0;

        doshdr = (PIMAGE_DOS_HEADER)data;

        if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;    

        nthdr = (PIMAGE_NT_HEADERS)(data + doshdr->e_lfanew);
        if (nthdr->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
            exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + data);
            image_size = nthdr32->OptionalHeader.SizeOfImage;
        }
        else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
            exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + data);
            image_size = nthdr64->OptionalHeader.SizeOfImage;
        }

        if (exportDir && ((char*)exportDir != data)) {
            functions = (PDWORD)(exportDir->AddressOfFunctions + data);
            ordinals = (PWORD)(exportDir->AddressOfNameOrdinals + data);
            names = (PDWORD)(exportDir->AddressOfNames + data);

            for ( i = 0; i < exportDir->NumberOfFunctions; i++ ) {
                if (functions[i]) {
                    if ((DWORD)(functions[i] + Base()) == address) {
                        for (unsigned j = 0; j < exportDir->NumberOfNames; j++ ) {
                            if ( ordinals[j] == i ) {
                                return (names[j] + data);
                            }
                        }
                    }
                }
            }
        }

        return NULL;
    }

    void PEImage::processBeforeDump(char* data, size_t size) {
        PIMAGE_DOS_HEADER doshdr;
        PIMAGE_NT_HEADERS nthdr;
        PIMAGE_NT_HEADERS32 nthdr32;
        PIMAGE_NT_HEADERS64 nthdr64;
        PIMAGE_SECTION_HEADER sechdr;
        unsigned short numsecs;
        unsigned short i;

        if (data && size > 0) {
            doshdr = (PIMAGE_DOS_HEADER)data;

            if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
                return;

            nthdr = (PIMAGE_NT_HEADERS)(data + doshdr->e_lfanew);
            if (nthdr->Signature != IMAGE_NT_SIGNATURE)
                return;

            if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
                nthdr32->OptionalHeader.ImageBase = (DWORD)Base();
                numsecs = nthdr32->FileHeader.NumberOfSections;
                if (size < sizeof(IMAGE_NT_HEADERS32) - 
                           sizeof(IMAGE_OPTIONAL_HEADER32) + 
                           sizeof(IMAGE_DOS_HEADER) + 
                           nthdr32->FileHeader.SizeOfOptionalHeader + 
                           (numsecs * sizeof(IMAGE_SECTION_HEADER)))
                    return;
                sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr32->OptionalHeader + nthdr32->FileHeader.SizeOfOptionalHeader);
                for (i = 0; i < numsecs; i++) {
                    sechdr[i].PointerToRawData = sechdr[i].VirtualAddress;
                    sechdr[i].SizeOfRawData = sechdr[i].Misc.VirtualSize;
                }
                // zero out the relocation table since relocations have already been applied
                if (nthdr32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                    nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                    nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
                    nthdr32->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
                }
            }
            else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
                nthdr64->OptionalHeader.ImageBase = Base();
                numsecs = nthdr64->FileHeader.NumberOfSections;
                if (size < sizeof(IMAGE_NT_HEADERS64) - 
                           sizeof(IMAGE_OPTIONAL_HEADER64) + 
                           sizeof(IMAGE_DOS_HEADER) + 
                           nthdr64->FileHeader.SizeOfOptionalHeader + 
                           (numsecs * sizeof(IMAGE_SECTION_HEADER)))
                    return;
                sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr64->OptionalHeader + nthdr64->FileHeader.SizeOfOptionalHeader);
                for (i = 0; i < numsecs; i++) {
                    sechdr[i].PointerToRawData = sechdr[i].VirtualAddress;
                    sechdr[i].SizeOfRawData = sechdr[i].Misc.VirtualSize;
                }
                // zero out the relocation table since relocations have already been applied
                if (nthdr64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                    nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                    nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
                    nthdr64->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
                }
            }
        }
    }

    const char* PEImage::getFileType() const {
        return "mz";
    }
}
