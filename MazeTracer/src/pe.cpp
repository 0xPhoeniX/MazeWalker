#include "pe.h"
#include <fstream>
#include <algorithm>
#include <sstream>
#include <map>
#include "crypto.h"
#include <Windows.h>
#include "cfg.h"
#include "arch_types.h"

using namespace std;

#define DATA_LEN 32

typedef struct 
{
	U_INT addr;
	WORD ordinal;
	char name[DATA_LEN + 1];
} API, *PAPI;

typedef struct _LIB
{
	DWORD api_num;
	PAPI apis;
	U_INT base;
	U_INT size;
} LIB, *PLIB;

typedef struct _MOD_INFO
{
	bool doMonitor;
	U_INT lower;
	U_INT upper;
	PLIB exported_apis;
} MOD_INFO, *PMOD_NFO;

map<U_INT, MOD_INFO> loaded_modules;
extern void log(std::string msg);
PLIB pe_dump_export_section(char* base);
bool isKnownPE(char* base, U_INT size);

void pe_init_subsystem()
{
	for (unsigned int i = 0; i < cfg.mods_whitelist.capacity(); i++)
		pe_watch_module(GetModuleHandleA(cfg.mods_whitelist[i].c_str()), (char*)0);
}

void pe_watch_module(void* module_base, const char* path)
{
	if (module_base && pe_is_valid_image((char*)module_base))
	{
		map<U_INT, MOD_INFO>::iterator moditer;
		bool do_trace = true;
		U_INT module_size = 0;

		moditer = loaded_modules.find((U_INT)module_base);
		if (pe_get_image_size((char*)module_base, module_size))
		{
			if (moditer == loaded_modules.end())
			{
				loaded_modules[(U_INT)module_base].doMonitor = do_trace;
				loaded_modules[(U_INT)module_base].lower = (U_INT)module_base;
				loaded_modules[(U_INT)module_base].upper = (U_INT)module_base + module_size;
				loaded_modules[(U_INT)module_base].exported_apis = pe_dump_export_section((char*)module_base);

				if (path)
				{
					for(U_INT i = 0; i < cfg.path_whitelist.capacity(); ++i)
						if(_strnicmp(cfg.path_whitelist[i].c_str(), path, strlen(cfg.path_whitelist[i].c_str())) == 0)
						{
							loaded_modules[(U_INT)module_base].doMonitor = false;
							return;
						}
				}

				if (isKnownPE((char*)module_base, module_size))
				{
					loaded_modules[(U_INT)module_base].doMonitor = false;
				}
			}
		}
	}
}

bool pe_address_trace_status(void* address)
{
	if (address)
	{
		map<U_INT, MOD_INFO>::iterator moditer;

		for (moditer = loaded_modules.begin(); moditer != loaded_modules.end(); moditer++)
		{
			if ((U_INT)address > moditer->second.lower &&
                (U_INT)address < moditer->second.upper)
                return moditer->second.doMonitor;
		}
	}

	return true;
}

PLIB pe_dump_export_section(char* base)
{
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_NT_HEADERS32 nthdr32;
	PIMAGE_NT_HEADERS64 nthdr64;
	PIMAGE_EXPORT_DIRECTORY exportDir; 
    DWORD i, image_size = 0;
    PDWORD functions = NULL;
	PWORD ordinals = NULL;
	PLIB lib = NULL;
	PDWORD names = NULL;
    
	if (base == NULL)
		return 0;

	doshdr = (PIMAGE_DOS_HEADER)base;

	if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;    

	nthdr = (PIMAGE_NT_HEADERS)(base + doshdr->e_lfanew);
	if (nthdr->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
		exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		image_size = nthdr32->OptionalHeader.SizeOfImage;
	}
	else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
		exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		image_size = nthdr64->OptionalHeader.SizeOfImage;
	}

	if (exportDir && ((char*)exportDir != base))
	{
		lib = (PLIB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LIB));

		if (lib)
		{
			lib->base = (U_INT)base;
			lib->size = image_size;
			lib->api_num = exportDir->NumberOfFunctions;

			lib->apis = (PAPI)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(API) * (lib->api_num + 1));
			if (lib->apis)
			{
				functions = (PDWORD)(exportDir->AddressOfFunctions + base);
				ordinals = (PWORD)(exportDir->AddressOfNameOrdinals + base);
				names = (PDWORD)(exportDir->AddressOfNames + base);

				for ( i = 0; i < exportDir->NumberOfFunctions; i++ )
				{
					if (functions[i])
					{
						lib->apis[i].addr = (U_INT)(functions[i] + base);
						for (unsigned j = 0; j < exportDir->NumberOfNames; j++ )
						{
							if ( ordinals[j] == i )
							{
								memcpy(lib->apis[i].name, (names[j] + base), DATA_LEN - 1);
								break;
							}
						}
					}
				}
			}
		}
	}

	return lib;
}

void FixPE(U_INT base, char *buf, U_INT bufsize)
{
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_NT_HEADERS32 nthdr32;
	PIMAGE_NT_HEADERS64 nthdr64;
	PIMAGE_SECTION_HEADER sechdr;
	unsigned short numsecs;
	unsigned short i;

	if (!base || !buf || !bufsize)
		return;

	doshdr = (PIMAGE_DOS_HEADER)buf;

	if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	if ((U_INT)doshdr->e_lfanew > bufsize - (sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_DOS_HEADER)))
		return;

	nthdr = (PIMAGE_NT_HEADERS)(buf + doshdr->e_lfanew);
	if (nthdr->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
		nthdr32->OptionalHeader.ImageBase = (DWORD)base;
		numsecs = nthdr32->FileHeader.NumberOfSections;
		if (bufsize < sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_OPTIONAL_HEADER32) + sizeof(IMAGE_DOS_HEADER) + nthdr32->FileHeader.SizeOfOptionalHeader + (numsecs * sizeof(IMAGE_SECTION_HEADER)))
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
		nthdr64->OptionalHeader.ImageBase = base;
		numsecs = nthdr64->FileHeader.NumberOfSections;
		if (bufsize < sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_OPTIONAL_HEADER64) + sizeof(IMAGE_DOS_HEADER) + nthdr64->FileHeader.SizeOfOptionalHeader + (numsecs * sizeof(IMAGE_SECTION_HEADER)))
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
	return;
}

void* pe_extract_image(void* base, size_t &size)
{
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_NT_HEADERS32 nthdr32;
	PIMAGE_NT_HEADERS64 nthdr64;
	PIMAGE_SECTION_HEADER sechdr;
	unsigned short numsecs;
	unsigned short i;
	char *pedata = NULL;
	U_INT pesize = 0, header_size = 0;
	MEMORY_BASIC_INFORMATION curr_info;

	if (!base)
		return 0;

	size = 0;
	doshdr = (PIMAGE_DOS_HEADER)base;

	if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	nthdr = (PIMAGE_NT_HEADERS)((U_INT)base + doshdr->e_lfanew);
	if (nthdr->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;

		if (nthdr32->OptionalHeader.SizeOfImage > 0)
		{
			// Calculate needed memory buffer
			header_size = pesize = nthdr32->OptionalHeader.SizeOfHeaders / 0x1000 * 0x1000 + 0x1000;
			numsecs = nthdr32->FileHeader.NumberOfSections;
			if (numsecs > 0)
			{
				sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr32->OptionalHeader + nthdr32->FileHeader.SizeOfOptionalHeader);
				pesize = pesize + sechdr[numsecs - 1].VirtualAddress + sechdr[numsecs - 1].Misc.VirtualSize;
			}
		}
	}
	else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;

		if (nthdr64->OptionalHeader.SizeOfImage > 0)
		{
			// Calculate needed memory buffer
			header_size = pesize = nthdr64->OptionalHeader.SizeOfHeaders / 0x1000 * 0x1000 + 0x1000;
			numsecs = nthdr64->FileHeader.NumberOfSections;
			if (numsecs > 0)
			{
				sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr64->OptionalHeader + nthdr64->FileHeader.SizeOfOptionalHeader);
				pesize = pesize + sechdr[numsecs - 1].VirtualAddress + sechdr[numsecs - 1].Misc.VirtualSize;
			}
		}
	}
	else
		return 0;

	if (pesize)
	{
		if (VirtualQuery(base, &curr_info, sizeof(curr_info)) == sizeof(curr_info))
		{
			if (curr_info.RegionSize > pesize)
				pesize = curr_info.RegionSize;

			pedata = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pesize);
			if (pedata)
			{
				memcpy(pedata, (void*)base, header_size);

				// Copy sections
				for (i = 0; i < numsecs; i++) {
					memcpy(pedata + sechdr[i].VirtualAddress, 
							(void*)((U_INT)base + sechdr[i].VirtualAddress), 
							sechdr[i].Misc.VirtualSize);
				}

				size = pesize;
				FixPE((U_INT)base, pedata, size);
			}
		}
	}

	return pedata;
}

bool pe_get_image_size(char *buf, size_t& size)
{
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_NT_HEADERS32 nthdr32;
	PIMAGE_NT_HEADERS64 nthdr64;

	if (buf == 0)
		goto error;

	doshdr = (PIMAGE_DOS_HEADER)buf;

	if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
		goto error;

	nthdr = (PIMAGE_NT_HEADERS)(buf + doshdr->e_lfanew);
	if (nthdr->Signature != IMAGE_NT_SIGNATURE)
		goto error;

	if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
		size = nthdr32->OptionalHeader.SizeOfImage;
		return true;
	}

	if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
		size = nthdr64->OptionalHeader.SizeOfImage;
		return true;
	}

error:
	return false;
}

bool pe_get_import_table_hash(char* base, char* imphash)
{
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
    
	if (base && imphash)
	{
		doshdr = (PIMAGE_DOS_HEADER)base;

		if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
			goto error;

		nthdr = (PIMAGE_NT_HEADERS)(base + doshdr->e_lfanew);
		if (nthdr->Signature != IMAGE_NT_SIGNATURE)
			goto error;

		if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
			nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
			importDir = (PIMAGE_IMPORT_DESCRIPTOR)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + base);
		}
		else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
			nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
			importDir = (PIMAGE_IMPORT_DESCRIPTOR)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + base);
		}

		if ((char*)importDir == base)
			goto error;

		while (importDir->Name)
		{
			if (strlen((PSTR)(importDir->Name + base)))
			{
				dllname = std::string((PSTR)(importDir->Name + base));
				std::transform(dllname.begin(), dllname.end(), dllname.begin(), tolower);
				dllname.erase(dllname.length() - 4, 4);

				if(importDir->OriginalFirstThunk!=0)
				{
					pHintName = base + importDir->OriginalFirstThunk;
				}
				else
				{
					pHintName = base + importDir->FirstThunk;
				}

				if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
					pimage_thunk_data = (PIMAGE_THUNK_DATA) pHintName;
					while(pimage_thunk_data && pimage_thunk_data->u1.AddressOfData != 0)
					{
						U_INT dwAPIaddress;

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
							pAPIName = std::string(base +  dwAPIaddress + 2);
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
						U_INT dwAPIaddress;

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
							pAPIName = std::string(base +  dwAPIaddress + 2);
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
			if (calc_buf_md5(imphashdata.c_str(), imphashdata.length(), imphash))
				goto error;
		}

		return true;
	}

error:
	return false;
}

bool pe_get_export_table_hash(char* base, char *exphash)
{
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_NT_HEADERS32 nthdr32;
	PIMAGE_NT_HEADERS64 nthdr64;
	PIMAGE_EXPORT_DIRECTORY exportDir = NULL; 
    U_INT i;
    PDWORD functions = NULL;
	PWORD ordinals = NULL;
	PDWORD name = NULL;
	std::string exphashdata;
    
	if (base && exphash)
	{
		doshdr = (PIMAGE_DOS_HEADER)base;

		if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
			goto error;    

		nthdr = (PIMAGE_NT_HEADERS)(base + doshdr->e_lfanew);
		if (nthdr->Signature != IMAGE_NT_SIGNATURE)
			goto error;

		if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
			nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
			exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		}
		else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
			nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
			exportDir = (PIMAGE_EXPORT_DIRECTORY)(nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		}

		if (exportDir && (char*)exportDir != base)
		{
			functions = (PDWORD)(exportDir->AddressOfFunctions + base);
			ordinals = (PWORD)(exportDir->AddressOfNameOrdinals + base);
			name = (PDWORD)(exportDir->AddressOfNames + base);

			for ( i = 0; i < exportDir->NumberOfFunctions; i++ )
			{
				for (unsigned j = 0; j < exportDir->NumberOfNames; j++ )
					if ( ordinals[j] == i )
					{
						exphashdata.append(std::string((char*)(name[j] + base)));
						exphashdata.append(",");
						break;
					}
			}

			if (exphashdata.length())
			{
				exphashdata.erase(exphashdata.length() - 1, 1);
				if (calc_buf_md5(exphashdata.c_str(), exphashdata.length(), exphash))
					goto error;
			}
		}

		return true;
	}

error:
	return false;
}

bool isKnownPE(char* base, U_INT size)
{
	std::vector<std::string>::iterator impiter;
	char hash[32+1] = {0};

	if (pe_get_import_table_hash(base, hash))
	{
		impiter = std::find(cfg.hash_whitelist.begin(), cfg.hash_whitelist.end(), std::string(hash));
		if (impiter != cfg.hash_whitelist.end())
		{
			log("Known module: " + string(hash) + "\n");
			return true;
		}
		log("unKnown module imphash: " + string(hash) +"\n");
	}

	if (pe_get_export_table_hash(base, hash))
	{
		impiter = std::find(cfg.hash_whitelist.begin(), cfg.hash_whitelist.end(), std::string(hash));
		if (impiter != cfg.hash_whitelist.end())
		{
			log("Known module: " + string(hash) + "\n");
			return true;
		}
		log("unKnown module exphash: " + string(hash) + "\n");
	}

	return false;
}

bool pe_is_valid_image(char* base)
{
	return (*(short*)base == 0x5a4d);
}

char* pe_find_exported_api_name(void* base, void* api_address)
{
	map<U_INT, MOD_INFO>::iterator moditer;
	char* api_name = NULL;
	PLIB api_info = NULL;

	moditer = loaded_modules.find((U_INT)base);
	if (moditer != loaded_modules.end())
	{
		if (moditer->second.exported_apis)
		{
			for (unsigned i = 0; i < moditer->second.exported_apis->api_num; i++)
			{
				if (moditer->second.exported_apis->apis[i].addr == (U_INT)api_address)
				{
					api_name = moditer->second.exported_apis->apis[i].name;
					break;
				}
			}
		}
	}
	return api_name;
}