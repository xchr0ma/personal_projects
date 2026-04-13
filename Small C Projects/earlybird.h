#ifndef EARLYBIRD_H      
#define EARLYBIRD_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifdef min
#error "min macro is defined!"
#endif

// Standard Windows Headers
#include <windows.h>           
#include <winternl.h>          
#include <processthreadsapi.h> 
#include <memoryapi.h>         

// C++ headers AFTER Windows
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <cstring>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")

// Helper macros for error handling
#define LOG_SUCCESS(msg) std::cout << "[+] " << msg << std::endl
#define LOG_ERROR(msg) std::cerr << "[-] " << msg << " (Error: " << GetLastError() << ")" << std::endl
#define LOG_INFO(msg) std::cout << "[*] " << msg << std::endl

#endif // Earlybirdh
