#ifndef _MAZEWALKER_PE_HELPER_H_
#define _MAZEWALKER_PE_HELPER_H_

// initialize watch module list from the configuration
void pe_init_subsystem();

// extract pe image from memory buffer and return it with fixed header
//		base - pe image base
//		size - result buffer size
//		returned - fixed image buffer (original buffer remains intact)
void* pe_extract_image(void* base, size_t &size);

// return buffer size as it was allocated in virtual memory
bool pe_get_image_size(char *buf, size_t& size);

// calculate imp hash for the given pe image
//		base - image base
//		imphash - calculated imp hash
bool pe_get_import_table_hash(char* base, char* imphash);

// calculate exp hash for the given pe image
//		base - image base
//		exphash - calculated exp hash
bool pe_get_export_table_hash(char* base, char *exphash);

// check if the image in buffer is valid
bool pe_is_valid_image(char* base);

// add module to the watch list by it's path and base address
void pe_watch_module(void* module_base, const char* path);

// find the api name by it's address
//		base - image base
//		api_address - the address of the api
char* pe_find_exported_api_name(void* base, void* api_address);

// check if the address must be grased based on the watch module list
//		address - address to test
bool pe_address_trace_status(void* address);

#endif