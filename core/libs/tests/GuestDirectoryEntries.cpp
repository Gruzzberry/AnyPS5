#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/File/include/File.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include "prx/libkernel/File/include/FileFlags.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

static void Check(bool value, int line) {
    if (!value) {
        std::fprintf(stderr, "Directory entry check failed at line %d\n", line);
        std::abort();
    }
}
#define Require(value) Check((value), __LINE__)

static constexpr int ErrorEinval = static_cast<int>(0x80020016u);
static constexpr int ErrorEfault = static_cast<int>(0x8002000Eu);
static constexpr int ErrorEbadf = static_cast<int>(0x80020009u);

struct Entry {
    std::uint8_t type;
    std::uint16_t recordLength;
    std::uint32_t fileNumber = 0;
};

static int Collect(const char* buffer, int bytes, std::map<std::string, Entry>& entries) {
    int records = 0;
    for (int offset = 0; offset < bytes; ++records) {
        std::uint16_t recordLength = 0;
        std::memcpy(&recordLength, buffer + offset + 4, sizeof(recordLength));
        const auto nameLength = static_cast<std::uint8_t>(buffer[offset + 7]);
        const std::string name(buffer + offset + 8);
        Require(name.size() == nameLength);
        Require(recordLength == ((8 + nameLength + 1 + 3) & ~3));
        Require(offset + recordLength <= bytes);
        std::uint32_t fileNumber = 0;
        std::memcpy(&fileNumber, buffer + offset, sizeof(fileNumber));
        Require(entries.emplace(name, Entry{static_cast<std::uint8_t>(buffer[offset + 6]), recordLength, fileNumber}).second);
        offset += recordLength;
    }
    return records;
}

int main() {
    const auto root = std::filesystem::path("anyps5-directory-entries-test-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Require(std::filesystem::create_directory(root));
    const std::string longName = "a-much-longer-entry-name-0123456789";
    { std::ofstream stream(root / "data.bin", std::ios::binary); stream << "0123456789"; }
    { std::ofstream stream(root / "b"); }
    { std::ofstream stream(root / longName); }
    Require(std::filesystem::create_directory(root / "sub"));

    const int directory = sceKernelOpen(root.string().c_str(), SCE_KERNEL_O_RDONLY | SCE_KERNEL_O_DIRECTORY, 0);
    Require(directory >= 0);
    std::array<char, 48> small{};
    std::map<std::string, Entry> entries;
    int calls = 0;
    std::int64_t previousBase = -1;
    for (;;) {
        std::int64_t base = -1;
        const int read = sceKernelGetdirentries(directory, small.data(), static_cast<int>(small.size()), &base);
        Require(read >= 0 && read <= static_cast<int>(small.size()));
        Require(base >= 0 && base != previousBase);
        if (calls == 0) Require(base == 0);
        previousBase = base;
        if (read == 0) break;
        Require(Collect(small.data(), read, entries) > 0);
        ++calls;
    }
    Require(calls >= 3);
    Require(entries.size() == 6);
    for (const char* name : {".", "..", "data.bin", "b", "sub"}) Require(entries.contains(name));
    Require(entries.contains(longName) && entries[longName].recordLength == 44);
    Require(entries["b"].recordLength == 12);
    Require(entries["sub"].type == 4 || entries["sub"].type == 0);
    Require(entries["data.bin"].type == 8 || entries["data.bin"].type == 0);

    Require(sceKernelLseek(directory, 0, 0) == 0);
    std::array<char, 8> tooSmall{};
    Require(sceKernelGetdents(directory, tooSmall.data(), static_cast<int>(tooSmall.size())) == ErrorEinval);
    Require(sceKernelGetdents(directory, nullptr, 64) == ErrorEfault);
    Require(sceKernelGetdents(directory, small.data(), 0) == ErrorEinval);
    std::array<char, 4096> large{};
    std::map<std::string, Entry> all;
    const int readAll = sceKernelGetdents(directory, large.data(), static_cast<int>(large.size()));
    Require(readAll > 0 && Collect(large.data(), readAll, all) == 6);
#ifdef _WIN32
    for (const auto& [name, entry] : all) {
        FileStat status{};
        Require(lstat_nid_postfix((root / name).string().c_str(), &status) == 0);
        Require(entry.fileNumber != 0 && entry.fileNumber == static_cast<std::uint32_t>(status.st_ino));
    }
#endif
    Require(sceKernelGetdents(directory, large.data(), static_cast<int>(large.size())) == 0);

    Require(sceKernelLseek(directory, 0, 0) == 0);
    Require(getdents_nid_postfix(directory, tooSmall.data(), static_cast<int>(tooSmall.size())) == -1 && *__error_nid_postfix() == 22);
    *__error_nid_postfix() = 0;
    Require(getdents_nid_postfix(directory, nullptr, 64) == -1 && *__error_nid_postfix() == 14);
    *__error_nid_postfix() = 0;
    Require(getdirentries_nid_postfix(directory, small.data(), 0, nullptr) == -1 && *__error_nid_postfix() == 22);
    std::int64_t posixBase = -1;
    *__error_nid_postfix() = 1234;
    const int firstPart = getdirentries_nid_postfix(directory, small.data(), static_cast<int>(small.size()), &posixBase);
    Require(firstPart > 0 && posixBase == 0 && *__error_nid_postfix() == 1234);
    const int secondPart = getdirentries_nid_postfix(directory, small.data(), static_cast<int>(small.size()), &posixBase);
    Require(secondPart > 0 && posixBase > 0 && *__error_nid_postfix() == 1234);
    Require(sceKernelLseek(directory, 0, 0) == 0);
    std::map<std::string, Entry> posix;
    const int posixRead = getdirentries_nid_postfix(directory, large.data(), static_cast<int>(large.size()), &posixBase);
    Require(posixRead == readAll && posixBase == 0 && Collect(large.data(), posixRead, posix) == 6);
    Require(getdents_nid_postfix(directory, large.data(), static_cast<int>(large.size())) == 0);
    Require(sceKernelLseek(directory, 0, 0) == 0);
    std::map<std::string, Entry> dents;
    const int dentsRead = getdents_nid_postfix(directory, large.data(), static_cast<int>(large.size()));
    Require(dentsRead == readAll && Collect(large.data(), dentsRead, dents) == 6);
    Require(sceKernelClose(directory) == 0);
    Require(getdents_nid_postfix(directory, large.data(), static_cast<int>(large.size())) == -1 && *__error_nid_postfix() == 9);
    *__error_nid_postfix() = 0;
    Require(getdirentries_nid_postfix(directory, large.data(), static_cast<int>(large.size()), nullptr) == -1 && *__error_nid_postfix() == 9);

    const int file = sceKernelOpen((root / "data.bin").string().c_str(), SCE_KERNEL_O_RDWR, 0);
    Require(file >= 0);
    Require(sceKernelLseek(file, 2, 0) == 2);
    char bytes[16] = {};
    Require(sceKernelPread(file, bytes, 4, 5) == 4 && std::memcmp(bytes, "5678", 4) == 0);
    Require(sceKernelLseek(file, 0, 1) == 2);
    Require(sceKernelPwrite(file, "XY", 2, 8) == 2);
    Require(sceKernelLseek(file, 0, 1) == 2);
    Require(sceKernelRead(file, bytes, 3) == 3 && std::memcmp(bytes, "234", 3) == 0);
    Require(sceKernelPread(file, bytes, sizeof(bytes), 0) == 10 && std::memcmp(bytes, "01234567XY", 10) == 0);
    Require(sceKernelPread(file, bytes, sizeof(bytes), 10) == 0);
    Require(sceKernelPread(file, bytes, 1, -1) == ErrorEinval);
    Require(sceKernelPwrite(file, nullptr, 1, 0) == ErrorEfault);
    Require(sceKernelClose(file) == 0);
    Require(sceKernelPread(file, bytes, 1, 0) == ErrorEbadf);

    std::filesystem::remove_all(root);

#ifdef _WIN32
    const auto numbered = std::filesystem::path("anyps5-directory-numbers-test-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Require(std::filesystem::create_directory(numbered));
    { std::ofstream stream(numbered / "target.bin", std::ios::binary); stream << "x"; }
    { std::ofstream stream(numbered / std::filesystem::path(u8"caf\u00e9.txt"), std::ios::binary); stream << "x"; }
    { std::ofstream stream(numbered / std::filesystem::path(u8"\u65e5\u672c.txt"), std::ios::binary); stream << "x"; }
    const bool linked = CreateSymbolicLinkW((numbered / "file-link").c_str(), L"target.bin", SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;
    const int numberedDirectory = sceKernelOpen(numbered.string().c_str(), SCE_KERNEL_O_RDONLY | SCE_KERNEL_O_DIRECTORY, 0);
    Require(numberedDirectory >= 0);
    const auto readNumbers = [&] {
        std::map<std::string, Entry> found;
        Require(sceKernelLseek(numberedDirectory, 0, 0) == 0);
        const int listed = sceKernelGetdents(numberedDirectory, large.data(), static_cast<int>(large.size()));
        Require(listed > 0);
        Collect(large.data(), listed, found);
        for (const auto& [name, entry] : found) {
            FileStat status{};
            Require(lstat_nid_postfix((numbered / name).string().c_str(), &status) == 0);
            Require(entry.fileNumber != 0 && entry.fileNumber == static_cast<std::uint32_t>(status.st_ino));
        }
        return found;
    };
    const auto before = readNumbers();
    Require(before.contains("caf\xc3\xa9.txt") && before.contains("\xe6\x97\xa5\xe6\x9c\xac.txt"));
    if (linked) Require(before.at("file-link").fileNumber != before.at("target.bin").fileNumber);
    { std::ofstream stream(numbered / "added.bin", std::ios::binary); stream << "x"; }
    const auto after = readNumbers();
    Require(after.contains("added.bin"));
    for (const auto& [name, entry] : before) Require(after.at(name).fileNumber == entry.fileNumber);
    Require(sceKernelClose(numberedDirectory) == 0);
    if (linked) Require(DeleteFileW((numbered / "file-link").c_str()) != 0);
    std::filesystem::remove_all(numbered);
#endif
}
