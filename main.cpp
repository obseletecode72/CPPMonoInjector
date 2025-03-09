#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>

namespace CPPMonoInjector {

    namespace Exceptions {
        class InjectorException : public std::runtime_error {
        public:
            InjectorException(const std::string& message) : std::runtime_error(message) {}
            InjectorException(const std::string& message, const std::exception& innerException)
                : std::runtime_error(message + ": " + innerException.what()) {}
        };
    }

    enum MonoImageOpenStatus {
        MONO_IMAGE_OK,
        MONO_IMAGE_ERROR_ERRNO,
        MONO_IMAGE_MISSING_ASSEMBLYREF,
        MONO_IMAGE_IMAGE_INVALID
    };

    struct ExportedFunction {
        std::string Name;
        void* Address;
        ExportedFunction(std::string name, void* address) : Name(name), Address(address) {}
    };

    namespace MemoryUtils {
        class Memory {
        private:
            HANDLE _handle;
            std::map<void*, int> _allocations;

        public:
            Memory(HANDLE processHandle) : _handle(processHandle) {}

            ~Memory() {
                for (const auto& kvp : _allocations) {
                    VirtualFreeEx(_handle, kvp.first, kvp.second, MEM_DECOMMIT);
                }
            }

            std::string ReadString(void* address, int length, const std::string& encoding) {
                std::vector<char> bytes;
                for (int i = 0; i < length; i++) {
                    char read;
                    SIZE_T bytesRead;
                    if (!ReadProcessMemory(_handle, (char*)address + i, &read, 1, &bytesRead)) {
                        throw Exceptions::InjectorException("Failed to read process memory");
                    }
                    if (read == 0x00) break;
                    bytes.push_back(read);
                }
                return std::string(bytes.begin(), bytes.end());
            }

            std::wstring ReadUnicodeString(void* address, int length) {
                std::vector<wchar_t> buffer(length / 2);
                SIZE_T bytesRead;
                if (!ReadProcessMemory(_handle, address, buffer.data(), length, &bytesRead)) {
                    throw Exceptions::InjectorException("Failed to read process memory");
                }
                return std::wstring(buffer.begin(), buffer.end());
            }

            short ReadShort(void* address) {
                short value;
                SIZE_T bytesRead;
                if (!ReadProcessMemory(_handle, address, &value, sizeof(value), &bytesRead)) {
                    throw Exceptions::InjectorException("Failed to read process memory");
                }
                return value;
            }

            int ReadInt(void* address) {
                int value;
                SIZE_T bytesRead;
                if (!ReadProcessMemory(_handle, address, &value, sizeof(value), &bytesRead)) {
                    throw Exceptions::InjectorException("Failed to read process memory");
                }
                return value;
            }

            long long ReadLong(void* address) {
                long long value;
                SIZE_T bytesRead;
                if (!ReadProcessMemory(_handle, address, &value, sizeof(value), &bytesRead)) {
                    throw Exceptions::InjectorException("Failed to read process memory");
                }
                return value;
            }

            std::vector<char> ReadBytes(void* address, int size) {
                std::vector<char> bytes(size);
                SIZE_T bytesRead;
                if (!ReadProcessMemory(_handle, address, bytes.data(), size, &bytesRead)) {
                    throw Exceptions::InjectorException("Failed to read process memory");
                }
                return bytes;
            }

            void* AllocateAndWrite(const std::vector<char>& data) {
                void* addr = Allocate(data.size());
                Write(addr, data);
                return addr;
            }

            void* AllocateAndWrite(const std::string& data) {
                std::vector<char> bytes(data.begin(), data.end());
                return AllocateAndWrite(bytes);
            }

            void* AllocateAndWrite(int data) {
                std::vector<char> bytes(sizeof(data));
                memcpy(bytes.data(), &data, sizeof(data));
                return AllocateAndWrite(bytes);
            }

            void* AllocateAndWrite(long long data) {
                std::vector<char> bytes(sizeof(data));
                memcpy(bytes.data(), &data, sizeof(data));
                return AllocateAndWrite(bytes);
            }

            void* Allocate(int size) {
                void* addr = VirtualAllocEx(_handle, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (addr == nullptr) {
                    throw Exceptions::InjectorException("Failed to allocate process memory");
                }
                _allocations[addr] = size;
                return addr;
            }

            void Write(void* addr, const std::vector<char>& data) {
                SIZE_T bytesWritten;
                if (!WriteProcessMemory(_handle, addr, data.data(), data.size(), &bytesWritten)) {
                    throw Exceptions::InjectorException("Failed to write process memory");
                }
            }
        };
    }

    namespace ProcessUtils {
        bool IsWow64Process2(HANDLE hProcess, USHORT* pProcessMachine, USHORT* pNativeMachine) {
            typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
            static IsWow64Process2_t pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process2");
            if (pIsWow64Process2) {
                return pIsWow64Process2(hProcess, pProcessMachine, pNativeMachine) != 0;
            }
            return false;
        }

        bool IsWow64Process(HANDLE hProcess, BOOL* wow64Process) {
            typedef BOOL(WINAPI* IsWow64Process_t)(HANDLE, BOOL*);
            static IsWow64Process_t pIsWow64Process = (IsWow64Process_t)GetProcAddress(GetModuleHandle("kernel32"), "IsWow64Process");
            if (pIsWow64Process) {
                return pIsWow64Process(hProcess, wow64Process) != 0;
            }
            return false;
        }

        bool Is64BitProcess(HANDLE handle) {
            try {
                SYSTEM_INFO si;
                GetNativeSystemInfo(&si);
                if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
                    return false;
                }
                std::string OSVer = "Windows 10";
                std::cout << OSVer << std::endl;
                if (OSVer.find("Windows 10") != std::string::npos) {
                    USHORT pMachine = 0, nMachine = 0;
                    if (IsWow64Process2(handle, &pMachine, &nMachine)) {
                        return pMachine != 332;
                    }
                }
                BOOL isWow64 = FALSE;
                if (IsWow64Process(handle, &isWow64)) {
                    return !isWow64;
                }
            }
            catch (const std::exception& ex) {
                std::ofstream log("DebugLog.txt", std::ios::app);
                log << "[ProcessUtils] is64Bit - ERROR: " << ex.what() << "\r\n";
            }
            return true;
        }

        std::vector<ExportedFunction> GetExportedFunctions(HANDLE handle, HMODULE mod) {
            std::vector<ExportedFunction> funcs;
            MemoryUtils::Memory memory(handle);
            int e_lfanew = memory.ReadInt((char*)mod + 0x3C);
            void* ntHeaders = (char*)mod + e_lfanew;
            void* optionalHeader = (char*)ntHeaders + 0x18;
            void* dataDirectory = (char*)optionalHeader + (Is64BitProcess(handle) ? 0x70 : 0x60);
            void* exportDirectory = (char*)mod + memory.ReadInt(dataDirectory);
            void* names = (char*)mod + memory.ReadInt((char*)exportDirectory + 0x20);
            void* ordinals = (char*)mod + memory.ReadInt((char*)exportDirectory + 0x24);
            void* functions = (char*)mod + memory.ReadInt((char*)exportDirectory + 0x1C);
            int count = memory.ReadInt((char*)exportDirectory + 0x18);
            for (int i = 0; i < count; i++) {
                try {
                    int offset = memory.ReadInt((char*)names + i * 4);
                    std::string name = memory.ReadString((char*)mod + offset, 32, "ASCII");
                    short ordinal = memory.ReadShort((char*)ordinals + i * 2);
                    void* address = (char*)mod + memory.ReadInt((char*)functions + ordinal * 4);
                    if (address != nullptr) {
                        funcs.emplace_back(name, address);
                    }
                }
                catch (...) {}
            }
            return funcs;
        }

        bool GetMonoModule(HANDLE handle, HMODULE* monoModule) {
            int size = Is64BitProcess(handle) ? 8 : 4;
            DWORD bytesNeeded;
            if (!EnumProcessModulesEx(handle, nullptr, 0, &bytesNeeded, LIST_MODULES_ALL)) {
                throw std::runtime_error("Failed to enumerate process modules");
            }
            int count = bytesNeeded / size;
            std::vector<HMODULE> ptrs(count);
            if (!EnumProcessModulesEx(handle, ptrs.data(), bytesNeeded, &bytesNeeded, LIST_MODULES_ALL)) {
                throw std::runtime_error("Failed to enumerate process modules");
            }
            for (int i = 0; i < count; i++) {
                try {
                    char path[MAX_PATH];
                    if (GetModuleFileNameExA(handle, ptrs[i], path, MAX_PATH)) {
                        std::string pathStr(path);
                        if (pathStr.find("mono") != std::string::npos) {
                            MODULEINFO info;
                            if (GetModuleInformation(handle, ptrs[i], &info, sizeof(info))) {
                                auto funcs = GetExportedFunctions(handle, ptrs[i]);
                                for (const auto& f : funcs) {
                                    if (f.Name == "mono_get_root_domain") {
                                        *monoModule = ptrs[i];
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
                catch (const std::exception& ex) {
                    std::ofstream log("DebugLog.txt", std::ios::app);
                    log << "[ProcessUtils] GetMono - ERROR: " << ex.what() << "\r\n";
                }
            }
            *monoModule = nullptr;
            return false;
        }
    }

    namespace Assembler {
        class Assembler {
        private:
            std::vector<unsigned char> __asm__;

        public:
            void MovRax(void* arg) {
                __asm__.insert(__asm__.end(), { 0x48, 0xB8 });
                long long value = (long long)arg;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void MovRcx(void* arg) {
                __asm__.insert(__asm__.end(), { 0x48, 0xB9 });
                long long value = (long long)arg;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void MovRdx(void* arg) {
                __asm__.insert(__asm__.end(), { 0x48, 0xBA });
                long long value = (long long)arg;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void MovR8(void* arg) {
                __asm__.insert(__asm__.end(), { 0x49, 0xB8 });
                long long value = (long long)arg;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void MovR9(void* arg) {
                __asm__.insert(__asm__.end(), { 0x49, 0xB9 });
                long long value = (long long)arg;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void SubRsp(unsigned char arg) {
                __asm__.insert(__asm__.end(), { 0x48, 0x83, 0xEC, arg });
            }

            void CallRax() {
                __asm__.insert(__asm__.end(), { 0xFF, 0xD0 });
            }

            void AddRsp(unsigned char arg) {
                __asm__.insert(__asm__.end(), { 0x48, 0x83, 0xC4, arg });
            }

            void MovRaxTo(void* dest) {
                __asm__.insert(__asm__.end(), { 0x48, 0xA3 });
                long long value = (long long)dest;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void Push(int arg) {
                if (arg < 128) {
                    __asm__.push_back(0x6A);
                    __asm__.push_back((unsigned char)arg);
                }
                else {
                    __asm__.push_back(0x68);
                    __asm__.insert(__asm__.end(), (unsigned char*)&arg, (unsigned char*)&arg + sizeof(arg));
                }
            }

            void MovEax(int arg) {
                __asm__.push_back(0xB8);
                __asm__.insert(__asm__.end(), (unsigned char*)&arg, (unsigned char*)&arg + sizeof(arg));
            }

            void CallEax() {
                __asm__.insert(__asm__.end(), { 0xFF, 0xD0 });
            }

            void AddEsp(unsigned char arg) {
                __asm__.insert(__asm__.end(), { 0x83, 0xC4, arg });
            }

            void MovEaxTo(void* dest) {
                __asm__.push_back(0xA3);
                int value = (int)dest;
                __asm__.insert(__asm__.end(), (unsigned char*)&value, (unsigned char*)&value + sizeof(value));
            }

            void Return() {
                __asm__.push_back(0xC3);
            }

            std::vector<unsigned char> ToByteArray() {
                return __asm__;
            }
        };
    }

    class Injector {
    private:
        static const std::string mono_get_root_domain;
        static const std::string mono_thread_attach;
        static const std::string mono_image_open_from_data;
        static const std::string mono_assembly_load_from_full;
        static const std::string mono_assembly_get_image;
        static const std::string mono_class_from_name;
        static const std::string mono_class_get_method_from_name;
        static const std::string mono_runtime_invoke;
        static const std::string mono_assembly_close;
        static const std::string mono_image_strerror;
        static const std::string mono_object_get_class;
        static const std::string mono_class_get_name;

        std::map<std::string, void*> Exports = {
            {mono_get_root_domain, nullptr},
            {mono_thread_attach, nullptr},
            {mono_image_open_from_data, nullptr},
            {mono_assembly_load_from_full, nullptr},
            {mono_assembly_get_image, nullptr},
            {mono_class_from_name, nullptr},
            {mono_class_get_method_from_name, nullptr},
            {mono_runtime_invoke, nullptr},
            {mono_assembly_close, nullptr},
            {mono_image_strerror, nullptr},
            {mono_object_get_class, nullptr},
            {mono_class_get_name, nullptr}
        };

        MemoryUtils::Memory _memory;
        void* _rootDomain;
        bool _attach;
        HANDLE _handle;
        HMODULE _mono;

    public:
        bool _is64Bit;

        Injector(const std::string& processName) : _memory(nullptr) {
            DWORD pid = GetProcessIdByName(processName);
            if (pid == 0) {
                throw Exceptions::InjectorException("Process not found: " + processName);
            }
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (process == nullptr) {
                throw Exceptions::InjectorException("Failed to open process");
            }
            _handle = process;
            _is64Bit = ProcessUtils::Is64BitProcess(_handle);
            if (!ProcessUtils::GetMonoModule(_handle, &_mono)) {
                throw Exceptions::InjectorException("Failed to find mono.dll in the target process");
            }
            _memory = MemoryUtils::Memory(_handle);
        }

        Injector(int processId) : _memory(nullptr) {
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
            if (process == nullptr) throw Exceptions::InjectorException("Failed to open process");
            _handle = process;
            _is64Bit = ProcessUtils::Is64BitProcess(_handle);
            if (!ProcessUtils::GetMonoModule(_handle, &_mono)) {
                throw Exceptions::InjectorException("Failed to find mono.dll in the target process");
            }
            _memory = MemoryUtils::Memory(_handle);
        }

        Injector(HANDLE processHandle, HMODULE monoModule) : _memory(processHandle) {
            if (processHandle == nullptr || monoModule == nullptr) {
                throw std::invalid_argument("Arguments cannot be zero");
            }
            _handle = processHandle;
            _mono = monoModule;
            _is64Bit = ProcessUtils::Is64BitProcess(_handle);
        }

        ~Injector() {
            CloseHandle(_handle);
        }

        void ObtainMonoExports() {
            auto funcs = ProcessUtils::GetExportedFunctions(_handle, _mono);
            for (const auto& ef : funcs) {
                if (Exports.find(ef.Name) != Exports.end()) {
                    Exports[ef.Name] = ef.Address;
                }
            }
            for (const auto& kvp : Exports) {
                if (kvp.second == nullptr) {
                    throw Exceptions::InjectorException("Failed to obtain the address of " + kvp.first + "()");
                }
            }
        }

        void* Inject(const std::vector<char>& rawAssembly, const std::string& namespace_, const std::string& className, const std::string& methodName) {
            if (rawAssembly.empty()) throw std::invalid_argument("rawAssembly cannot be empty");
            if (className.empty()) throw std::invalid_argument("className cannot be empty");
            if (methodName.empty()) throw std::invalid_argument("methodName cannot be empty");
            ObtainMonoExports();
            _rootDomain = GetRootDomain();
            void* rawImage = OpenImageFromData(rawAssembly);
            _attach = true;
            void* assembly = OpenAssemblyFromImage(rawImage);
            void* image = GetImageFromAssembly(assembly);
            void* class_ = GetClassFromName(image, namespace_, className);
            void* method = GetMethodFromName(class_, methodName);
            RuntimeInvoke(method);
            return assembly;
        }

        void Eject(void* assembly, const std::string& namespace_, const std::string& className, const std::string& methodName) {
            if (assembly == nullptr) throw std::invalid_argument("assembly cannot be zero");
            if (className.empty()) throw std::invalid_argument("className cannot be empty");
            if (methodName.empty()) throw std::invalid_argument("methodName cannot be empty");
            ObtainMonoExports();
            _rootDomain = GetRootDomain();
            _attach = true;
            void* image = GetImageFromAssembly(assembly);
            void* class_ = GetClassFromName(image, namespace_, className);
            void* method = GetMethodFromName(class_, methodName);
            RuntimeInvoke(method);
            CloseAssembly(assembly);
        }

    private:
        DWORD GetProcessIdByName(const std::string& processName) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return 0;
            }
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (!Process32First(hSnapshot, &pe32)) {
                CloseHandle(hSnapshot);
                return 0;
            }
            do {
                if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &pe32));
            CloseHandle(hSnapshot);
            return 0;
        }

        void ThrowIfNull(void* ptr, const std::string& methodName) {
            if (ptr == nullptr) throw Exceptions::InjectorException(methodName + "() returned NULL");
        }

        void* GetRootDomain() {
            void* rootDomain = Execute(Exports[mono_get_root_domain], {});
            ThrowIfNull(rootDomain, mono_get_root_domain);
            return rootDomain;
        }

        void* OpenImageFromData(const std::vector<char>& assembly) {
            void* statusPtr = _memory.Allocate(4);
            void* rawImage = Execute(Exports[mono_image_open_from_data],
                { _memory.AllocateAndWrite(assembly), (void*)assembly.size(), (void*)1, statusPtr });
            MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);
            if (status != MonoImageOpenStatus::MONO_IMAGE_OK) {
                void* messagePtr = Execute(Exports[mono_image_strerror], { (void*)status });
                std::string message = _memory.ReadString(messagePtr, 256, "UTF-8");
                throw Exceptions::InjectorException(mono_image_open_from_data + "() failed: " + message);
            }
            return rawImage;
        }

        void* OpenAssemblyFromImage(void* image) {
            void* statusPtr = _memory.Allocate(4);
            void* assembly = Execute(Exports[mono_assembly_load_from_full],
                { image, _memory.AllocateAndWrite(std::vector<char>(1)), statusPtr, nullptr });
            MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);
            if (status != MonoImageOpenStatus::MONO_IMAGE_OK) {
                void* messagePtr = Execute(Exports[mono_image_strerror], { (void*)status });
                std::string message = _memory.ReadString(messagePtr, 256, "UTF-8");
                throw Exceptions::InjectorException(mono_assembly_load_from_full + "() failed: " + message);
            }
            return assembly;
        }

        void* GetImageFromAssembly(void* assembly) {
            void* image = Execute(Exports[mono_assembly_get_image], { assembly });
            ThrowIfNull(image, mono_assembly_get_image);
            return image;
        }

        void* GetClassFromName(void* image, const std::string& namespace_, const std::string& className) {
            void* class_ = Execute(Exports[mono_class_from_name],
                { image, _memory.AllocateAndWrite(namespace_), _memory.AllocateAndWrite(className) });
            ThrowIfNull(class_, mono_class_from_name);
            return class_;
        }

        void* GetMethodFromName(void* class_, const std::string& methodName) {
            void* method = Execute(Exports[mono_class_get_method_from_name],
                { class_, _memory.AllocateAndWrite(methodName), nullptr });
            ThrowIfNull(method, mono_class_get_method_from_name);
            return method;
        }

        std::string GetClassName(void* monoObject) {
            void* class_ = Execute(Exports[mono_object_get_class], { monoObject });
            ThrowIfNull(class_, mono_object_get_class);
            void* className = Execute(Exports[mono_class_get_name], { class_ });
            ThrowIfNull(className, mono_class_get_name);
            return _memory.ReadString(className, 256, "UTF-8");
        }

        std::string ReadMonoString(void* monoString) {
            int len = _memory.ReadInt((char*)monoString + (_is64Bit ? 0x10 : 0x8));
            std::wstring wstr = _memory.ReadUnicodeString((char*)monoString + (_is64Bit ? 0x14 : 0xC), len * 2);
            return std::string(wstr.begin(), wstr.end());
        }

        void RuntimeInvoke(void* method) {
            void* excPtr = _is64Bit ? _memory.AllocateAndWrite((long long)0) : _memory.AllocateAndWrite(0);
            void* result = Execute(Exports[mono_runtime_invoke],
                { method, nullptr, nullptr, excPtr });
            void* exc = (void*)_memory.ReadInt(excPtr);
            if (exc != nullptr) {
                std::string className = GetClassName(exc);
                std::string message = ReadMonoString((void*)_memory.ReadInt((char*)exc + (_is64Bit ? 0x20 : 0x10)));
                throw Exceptions::InjectorException("The managed method threw an exception: (" + className + ") " + message);
            }
        }

        void CloseAssembly(void* assembly) {
            void* result = Execute(Exports[mono_assembly_close], { assembly });
            ThrowIfNull(result, mono_assembly_close);
        }

        void* Execute(void* address, const std::vector<void*>& args) {
            void* retValPtr = _is64Bit ? _memory.AllocateAndWrite((long long)0) : _memory.AllocateAndWrite(0);
            Assembler::Assembler __asm_;
            if (_is64Bit) {
                __asm_.SubRsp(40);
                if (_attach) {
                    __asm_.MovRax(Exports[mono_thread_attach]);
                    __asm_.MovRcx(_rootDomain);
                    __asm_.CallRax();
                }
                __asm_.MovRax(address);
                for (size_t i = 0; i < args.size() && i < 4; i++) {
                    switch (i) {
                    case 0: __asm_.MovRcx(args[i]); break;
                    case 1: __asm_.MovRdx(args[i]); break;
                    case 2: __asm_.MovR8(args[i]); break;
                    case 3: __asm_.MovR9(args[i]); break;
                    }
                }
                __asm_.CallRax();
                __asm_.AddRsp(40);
                __asm_.MovRaxTo(retValPtr);
                __asm_.Return();
            }
            else {
                if (_attach) {
                    __asm_.Push((int)(long long)_rootDomain);
                    __asm_.MovEax((int)(long long)Exports[mono_thread_attach]);
                    __asm_.CallEax();
                    __asm_.AddEsp(4);
                }
                for (int i = args.size() - 1; i >= 0; i--) {
                    __asm_.Push((int)(long long)args[i]);
                }
                __asm_.MovEax((int)(long long)address);
                __asm_.CallEax();
                __asm_.AddEsp((unsigned char)(args.size() * 4));
                __asm_.MovEaxTo(retValPtr);
                __asm_.Return();
            }
            std::vector<unsigned char> code = __asm_.ToByteArray();
            std::vector<char> codeSigned(code.begin(), code.end());
            void* alloc = _memory.AllocateAndWrite(codeSigned);
            HANDLE thread = CreateRemoteThread(_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)alloc, nullptr, 0, nullptr);
            if (thread == nullptr) throw Exceptions::InjectorException("Failed to create a remote thread");
            WaitForSingleObject(thread, INFINITE);
            void* ret = _is64Bit ? (void*)_memory.ReadLong(retValPtr) : (void*)_memory.ReadInt(retValPtr);
            if ((long long)ret == 0xC0000005) {
                throw Exceptions::InjectorException("An access violation occurred during execution");
            }
            CloseHandle(thread);
            return ret;
        }
    };

    const std::string Injector::mono_get_root_domain = "mono_get_root_domain";
    const std::string Injector::mono_thread_attach = "mono_thread_attach";
    const std::string Injector::mono_image_open_from_data = "mono_image_open_from_data";
    const std::string Injector::mono_assembly_load_from_full = "mono_assembly_load_from_full";
    const std::string Injector::mono_assembly_get_image = "mono_assembly_get_image";
    const std::string Injector::mono_class_from_name = "mono_class_from_name";
    const std::string Injector::mono_class_get_method_from_name = "mono_class_get_method_from_name";
    const std::string Injector::mono_runtime_invoke = "mono_runtime_invoke";
    const std::string Injector::mono_assembly_close = "mono_assembly_close";
    const std::string Injector::mono_image_strerror = "mono_image_strerror";
    const std::string Injector::mono_object_get_class = "mono_object_get_class";
    const std::string Injector::mono_class_get_name = "mono_class_get_name";

    namespace ConsoleUtils {
        class CommandLineArguments {
        private:
            std::vector<std::string> _args;

        public:
            CommandLineArguments(const std::vector<std::string>& args) : _args(args) {}

            bool IsSwitchPresent(const std::string& name) {
                for (const auto& arg : _args) {
                    if (arg == name) return true;
                }
                return false;
            }

            bool GetLongArg(const std::string& name, long long& value) {
                std::string str;
                if (GetStringArg(name, str)) {
                    std::istringstream iss(str);
                    if (str.find("0x") == 0) {
                        iss >> std::hex >> value;
                    }
                    else {
                        iss >> value;
                    }
                    return !iss.fail();
                }
                value = 0;
                return false;
            }

            bool GetIntArg(const std::string& name, int& value) {
                std::string str;
                if (GetStringArg(name, str)) {
                    std::istringstream iss(str);
                    if (str.find("0x") == 0) {
                        iss >> std::hex >> value;
                    }
                    else {
                        iss >> value;
                    }
                    return !iss.fail();
                }
                value = 0;
                return false;
            }

            bool GetStringArg(const std::string& name, std::string& value) {
                for (size_t i = 0; i < _args.size(); i++) {
                    if (_args[i] == name && i + 1 < _args.size()) {
                        value = _args[i + 1];
                        return true;
                    }
                }
                value = "";
                return false;
            }
        };
    }

    namespace Console {
        void PrintHelp() {
            std::cout << "CPPMonoInjector 1.0, inspired on wh0am1 CPPMonoInjector Project\r\n\r\n"
                << "Usage:\r\n"
                << "CPPMonoInjector.exe <inject/eject> <options>\r\n\r\n"
                << "Options:\r\n"
                << "-p - The ID or the NAME of the target process\r\n"
                << "-a - When injecting, the path of the assembly to inject. When ejecting, the address of the assembly to eject\r\n"
                << "-n - The namespace in which the loader class resides\r\n"
                << "-c - The name of the loader class\r\n"
                << "-m - The name of the method to invoke in the loader class\r\n\r\n"
                << "Examples:\r\n"
                << "CPPMonoInjector.exe inject -p testgame.exe -a ExampleAssembly.dll -n ExampleAssembly -c Loader -m Load\r\n"
                << "CPPMonoInjector.exe eject -p testgame.exe -a 0x13D23A98 -n ExampleAssembly -c Loader -m Unload\r\n";
        }

        bool IsElevated() {
            BOOL fIsElevated = FALSE;
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation;
                DWORD dwSize;
                if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                    fIsElevated = elevation.TokenIsElevated;
                }
                CloseHandle(hToken);
            }
            return fIsElevated != 0;
        }

        void Inject(Injector& injector, ConsoleUtils::CommandLineArguments& args) {
            std::string assemblyPath, namespace_, className, methodName;
            if (!args.GetStringArg("-a", assemblyPath)) {
                std::cout << "No assembly specified" << std::endl;
                return;
            }
            std::vector<char> assembly;
            std::ifstream file(assemblyPath, std::ios::binary);
            if (!file) {
                std::cout << "Could not read the file " << assemblyPath << std::endl;
                return;
            }
            assembly.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            args.GetStringArg("-n", namespace_);
            if (!args.GetStringArg("-c", className)) {
                std::cout << "No class name specified" << std::endl;
                return;
            }
            if (!args.GetStringArg("-m", methodName)) {
                std::cout << "No method name specified" << std::endl;
                return;
            }
            try {
                void* remoteAssembly = injector.Inject(assembly, namespace_, className, methodName);
                if (remoteAssembly) {
                    std::cout << assemblyPath << ": 0x" << std::hex << (injector._is64Bit ? (long long)remoteAssembly : (int)remoteAssembly) << std::endl;
                }
            }
            catch (const Exceptions::InjectorException& ie) {
                std::cout << "Failed to inject assembly: " << ie.what() << std::endl;
            }
            catch (const std::exception& exc) {
                std::cout << "Failed to inject assembly (unknown error): " << exc.what() << std::endl;
            }
        }

        void Eject(Injector& injector, ConsoleUtils::CommandLineArguments& args) {
            std::string namespace_, className, methodName;
            long long assemblyPtr;
            if (!args.GetLongArg("-a", assemblyPtr)) {
                std::cout << "No assembly pointer specified" << std::endl;
                return;
            }
            void* assembly = (void*)assemblyPtr;
            args.GetStringArg("-n", namespace_);
            if (!args.GetStringArg("-c", className)) {
                std::cout << "No class name specified" << std::endl;
                return;
            }
            if (!args.GetStringArg("-m", methodName)) {
                std::cout << "No method name specified" << std::endl;
                return;
            }
            try {
                injector.Eject(assembly, namespace_, className, methodName);
                std::cout << "Ejection successful" << std::endl;
            }
            catch (const Exceptions::InjectorException& ie) {
                std::cout << "Ejection failed: " << ie.what() << std::endl;
            }
            catch (const std::exception& exc) {
                std::cout << "Ejection failed (unknown error): " << exc.what() << std::endl;
            }
        }
    }
}

// almost every game is memory protected, map your driver/implement it and do your shit
int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);
    if (args.size() < 2) {
        CPPMonoInjector::Console::PrintHelp();
        return 0;
    }
    if (!CPPMonoInjector::Console::IsElevated()) {
        std::cout << "\r\nCPPMonoInjector 1.0 curseduefi\r\n\r\nWARNING: You are running this in an unprivileged process, try from an Elevated Command Prompt.\r\n";
        std::cout << "\t As an alternative, right-click Game .exe and uncheck the Compatibility\r\n\t setting 'Run this program as Administrator'.\r\n\r\n";
    }
    CPPMonoInjector::ConsoleUtils::CommandLineArguments cla(args);
    bool inject = cla.IsSwitchPresent("inject");
    bool eject = cla.IsSwitchPresent("eject");
    if (!inject && !eject) {
        std::cout << "No operation (inject/eject) specified" << std::endl;
        return 0;
    }
    int pid;
    std::string pname;
    CPPMonoInjector::Injector* injector = nullptr;
    if (cla.GetIntArg("-p", pid)) {
        injector = new CPPMonoInjector::Injector(pid);
    }
    else if (cla.GetStringArg("-p", pname)) {
        injector = new CPPMonoInjector::Injector(pname);
    }
    else {
        std::cout << "No process id specified" << std::endl;
        return 0;
    }
    if (inject) CPPMonoInjector::Console::Inject(*injector, cla);
    else CPPMonoInjector::Console::Eject(*injector, cla);
    delete injector;
    return 0;
}
