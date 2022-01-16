#include <iostream>
#include "Windows.h"

void TestCreateFile() {
    HANDLE hndl = CreateFileA("dummy.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (hndl == INVALID_HANDLE_VALUE) {
        hndl = 0;
    }
}

int main()
{
    std::cout << "Hello World!\n";

    // Test refference count
    TestCreateFile();
    TestCreateFile();

    // Test api analyzer
    void* addr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, 0x40);
    std::cout << "VirtualAlloc: " << std::hex << addr << "\n";
    if (addr == NULL) {
        return 1;
    }

    // Test api analyzer
    UnmapViewOfFile(addr);

    return 0;
}