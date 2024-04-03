// some fun with memory
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

//function to read int from memory address
int ReadInt(HANDLE hProcess, uintptr_t address)
{
    // create somewhere in memory to store value
    int intValue = 0;

    // read memory
    ReadProcessMemory(hProcess, (BYTE*)address, &intValue, sizeof(intValue), nullptr);

    // return value
    return intValue;
}

// function to write to int in memory address
bool WriteInt(HANDLE hProcess, uintptr_t address, int newValue) 
{
    return WriteProcessMemory(hProcess, (BYTE*)address, &newValue, sizeof(newValue), nullptr);
}

// function to get process handle
HANDLE getProcHandle(DWORD procId) 
{
    // initialize a new handle
    HANDLE hProcess = 0;

    // get that handle
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procId);

    // if the handle is invalid, return 0
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    return hProcess;
}

// function to get process id
DWORD GetProcId(const std::wstring& processName) 
{
    // declare a PROCESSENTRY32 structure
    PROCESSENTRY32 processInfo;

    // set the size of the strucutre
    processInfo.dwSize = sizeof(processInfo);

    // take a snapshot of all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    // if the snapshot handle is invalid, return 0
    if (snapshot == INVALID_HANDLE_VALUE) 
    {
        return 0;
    }

    // get the first process from the snapshot
    Process32First(snapshot, &processInfo);

    // if the process name matches
    if (!processName.compare(processInfo.szExeFile)) 
    {
        // close handle
        CloseHandle(snapshot);

        // return correct PID
        return processInfo.th32ProcessID;
    }

    // loop through remaining processes
    while (Process32Next(snapshot, &processInfo)) 
    {
        // if match
        if (!processName.compare(processInfo.szExeFile)) 
        {
            // close handle
            CloseHandle(snapshot);

            // return correct PID
            return processInfo.th32ProcessID;
        }
    }

    // couldn't find valid result :(

    // close handle
    CloseHandle(snapshot);

    // return no result
    return 0;
}

// function to return module base address
uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    // initialize to zero for error checking
    uintptr_t modBaseAddr = 0;

    // get a handle to a snapshot of all modules
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

    // check if it's valid
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        // this struct holds the actual module information
        MODULEENTRY32 modEntry;

        // this is required for the function to work
        modEntry.dwSize = sizeof(modEntry);

        // If a module exists, get it's entry
        if (Module32First(hSnap, &modEntry))
        {
            // loop through the modules
            do
            {
                // compare the module name against ours
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    // copy the base address and break out of the loop
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }

                // each iteration we grab the next module entry
            } while (Module32Next(hSnap, &modEntry));
        }
    }

    // free the handle
    CloseHandle(hSnap);
    return modBaseAddr;
}

int main() 
{
    static int timer_value = 0;
    // std::cout << "[<] Program: ";
    // std::wstring input;
    // std::getline(std::wcin, input);

    //std::cout << "\n";

    // override
    std::wstring process = L"WINMINE.EXE";
    DWORD pid = GetProcId(process.c_str());

    HANDLE hProcess = getProcHandle(pid);

    if (pid != 0) 
    {
        std::cout << "[+] PID: " << std::dec << pid << "\n";
    }
    else 
    {
        std::cout << "[!] PID not found\n";
    }

    uintptr_t BaseAddr = GetModuleBaseAddress(pid, process.c_str());

    if (BaseAddr != 0) 
    {
        std::cout << "[+] Base Address: 0x" << std::hex << BaseAddr << "\n";
    }
    else 
    {
        std::cout << "[!] Base Address not found\n";
    }

    uintptr_t TimerAddr = BaseAddr + 0x579C;

    if (TimerAddr == 0x579C) 
    {
        std::cout << "[!] Invalid Base Address with Offset\n";
    }
    else 
    {
        std::cout << "[+] Timer Address: 0x" << std::hex << TimerAddr << "\n";
    }

    while (true) 
    {
        while (timer_value != ReadInt(hProcess, TimerAddr))
        {
            if (timer_value == 5) 
            {
                timer_value = ReadInt(hProcess, TimerAddr);
                std::cout << "[*] Timer value: " << std::dec << timer_value << "\n";
                std::cout << "[%] Overwriting Timer Value to 0...\n";
                bool result = WriteInt(hProcess, TimerAddr, 0);
                if (result)
                {
                    std::cout << "[%] Success!\n";
                }
                else
                {
                    std::cout << "[!] Error writing to memory!\n";
                }
            }
            else 
            {
                timer_value = ReadInt(hProcess, TimerAddr);
                std::cout << "[*] Timer value: " << std::dec << timer_value << "\n";
            }
        }
    }
}