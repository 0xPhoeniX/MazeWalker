#include "pin.H"
#include "mazewarker.h"
#include <map>
#include <string>
#include <list>
#include "pe.h"
#include "cfg.h"

extern struct {ADDRINT base; ADDRINT limit;} stack_bases[THREAD_LIMIT];
std::list<W::MEMORY_BASIC_INFORMATION> alloc_info;

bool DoTrace(ADDRINT address)
{
	list<W::MEMORY_BASIC_INFORMATION>::iterator iter;

	if (pe_address_trace_status((void*)address))
	{
		ADDRINT AllocationBase, region_size;
		W::MEMORY_BASIC_INFORMATION m_info;

		for (iter = alloc_info.begin(); iter != alloc_info.end(); iter++)
		{
			if (address >= (ADDRINT)iter->AllocationBase && 
				address <= (iter->RegionSize + (ADDRINT)iter->BaseAddress))
			{
				return true;
			}
		}

		if (get_address_info(address, AllocationBase, region_size, &m_info))
		{
			pe_watch_module((char*)AllocationBase, (char*)0);
			if (pe_address_trace_status((void*)address))
			{
				alloc_info.push_back(m_info);
				return true;
			}

			return false;
		}

		return true;
	}

    return false;
}

void add_mutation(ADDRINT base_addr, void* mutation, ADDRINT size, ADDRINT entry_point)
{
    PCODE_BLOCK new_mutation = NULL;
	ADDRINT key = base_addr;

    if (mutation && size)
    {
        new_mutation = (PCODE_BLOCK)W::HeapAlloc(W::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CODE_BLOCK));
        if (new_mutation)
        {
            new_mutation->code = (char*)mutation;
            new_mutation->size = size;
            new_mutation->bbls = new std::list<ADDRINT>;
			new_mutation->tids = new std::list<ADDRINT>;
            new_mutation->bbls->push_back(block_id);
			new_mutation->id = mem_reg_id;
			new_mutation->entry = entry_point;

			if (mem_reg_id == 0)
				tfuncs[0] = entry_point;

			mem_info[key].code.push_back(new_mutation);
        }
    }
}

bool get_address_info(ADDRINT addr, ADDRINT& base, ADDRINT& size, W::MEMORY_BASIC_INFORMATION* info)
{
	list<W::MEMORY_BASIC_INFORMATION>::iterator iter;
	W::MEMORY_BASIC_INFORMATION curr_info;
	bool found = false;

	if (addr >= stack_bases[PIN_ThreadId()].limit && addr <= stack_bases[PIN_ThreadId()].base)
	{
		if (W::VirtualQuery((W::PVOID)addr, &curr_info, sizeof(curr_info)) &&
		// now mbi.AllocationBase = reserved stack memory base address

		W::VirtualQuery(curr_info.AllocationBase, &curr_info, sizeof(curr_info)) &&
		// now (mbi.BaseAddress, mbi.RegionSize) describe reserved (uncommitted) portion of the stack
		// skip it

		W::VirtualQuery((char*)curr_info.BaseAddress + curr_info.RegionSize, &curr_info, sizeof(curr_info)) &&
		// now (mbi.BaseAddress, mbi.RegionSize) describe the guard page
		// skip it

			W::VirtualQuery((char*)curr_info.BaseAddress + curr_info.RegionSize, &curr_info, sizeof(curr_info)))
		{
			LOG("\nAccessible stack\n\tAllocation base: " + 
				hexstr((ADDRINT)curr_info.AllocationBase) + 
				"\n\tQuery base " + hexstr((ADDRINT)curr_info.BaseAddress) +
				"\n\tSize " + hexstr((UINT32)(curr_info.RegionSize)) + 
				"\n\tType: " + hexstr((UINT32)curr_info.Type) + 
				"\n\tState " + hexstr((UINT32)curr_info.State) + "\n");
			// now (mbi.BaseAddress, mbi.RegionSize) describe the committed (i.e. accessed) portion of the stack

			size = curr_info.RegionSize;
			base = (ADDRINT)curr_info.BaseAddress;
			found = true;
		}
	}
	else
		if (W::VirtualQuery((W::PVOID)(addr / 0x1000 * 0x1000), &curr_info, sizeof(curr_info)))
		{
			size = curr_info.RegionSize + ((ADDRINT)curr_info.BaseAddress - (ADDRINT)curr_info.AllocationBase);
			base = (ADDRINT)curr_info.AllocationBase;
			found = true;
		}

	if (found && info)
		*info = curr_info;

	return found;
}

char* dump_memory_region(char* buffer, ADDRINT size, ADDRINT &result_size)
{
	char* ftype = "mem", *buf = buffer;
	char fname[128] = {0};
	FILE* dump;

	result_size = size;
	if (pe_is_valid_image(buffer))
	{
		ftype = "mz";
		buf = (char*)pe_extract_image(buffer, result_size);
	}
	else
	{
		buf = (char*)W::HeapAlloc(W::GetProcessHeap(), HEAP_ZERO_MEMORY, size);
		if (buf)
		{
			memcpy(buf, buffer, size);
		}
	}

	if (buf)
	{
		sprintf_s<sizeof(fname)>(fname, "%d_%x_%x_%d.%s",  
								 mem_reg_id, 
								 (ADDRINT)buffer, 
								 result_size, 
								 W::GetCurrentProcessId(), ftype);
		string output_path = cfg.output_dir + "\\" + string(fname);
		fopen_s(&dump, output_path.c_str(), "wb");
		fwrite(buf, sizeof(char), result_size, dump);
		fclose(dump);

		return buf;
	}

	return NULL;
}

bool memory_monitor(ADDRINT addr, ADDRINT tsize)
{
    ADDRINT region_size = 0, dump_size = 0;
    ADDRINT key;
	char* buf = NULL, *dump = NULL;
	std::list<PCODE_BLOCK>::iterator iter;
	ADDRINT AllocationBase;

    if (get_address_info(addr, AllocationBase, region_size, NULL))
    {
		buf = (char*)AllocationBase;
		key = (ADDRINT)AllocationBase;

        if (mem_info.find(key) == mem_info.end())
        {
			mem_info[key].base = (ADDRINT)buf;
			dump = dump_memory_region(buf, region_size, dump_size);
            add_mutation(key, dump, dump_size, addr);
            mem_info[key].id = mem_reg_id++;
			mem_info[key].pid = (UINT32)W::GetCurrentProcessId();
        }
		else
		{
			ADDRINT offset = addr - mem_info[key].base;
                
			for (iter = mem_info[key].code.begin(); iter != mem_info[key].code.end(); iter++)
			{
				if (offset <= (*iter)->size && addr >= mem_info[key].base)
				{
					if (memcmp(buf + offset, (*iter)->code + offset, tsize) == 0)
					{
						(*iter)->bbls->push_back(block_id);
						goto exit;
					}
				}
			}

			dump = dump_memory_region(buf, region_size, dump_size);
			add_mutation(key, dump, dump_size, addr);
			mem_reg_id++;
		}
    }

exit:
    return true;
}