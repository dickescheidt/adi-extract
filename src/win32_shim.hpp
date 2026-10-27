#pragma once
// Minimal Win32 compatibility layer for POSIX builds of adi-extract.
// Only the subset of the API that this project uses is emulated.
// Sparse-file semantics come for free from ftruncate() on ext4/xfs/btrfs.

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <climits>
#include <limits>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include "text.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifndef WINAPI
#define WINAPI
#endif

using DWORD = uint32_t;
using LONG = int32_t;
using ULONG = uint32_t;
using USHORT = uint16_t;
using LONGLONG = int64_t;
using BOOL = int;
using HANDLE = void*;
using HMODULE = void*;
using PUCHAR = unsigned char*;
using PULONG = ULONG*;

struct LARGE_INTEGER {
  LONGLONG QuadPart = 0;
};

#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1)))

constexpr DWORD INVALID_FILE_ATTRIBUTES = 0xffffffffu;
constexpr DWORD GENERIC_READ = 0x80000000u;
constexpr DWORD GENERIC_WRITE = 0x40000000u;
constexpr DWORD FILE_SHARE_READ = 0x00000001u;
constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080u;
constexpr DWORD FILE_FLAG_RANDOM_ACCESS = 0x10000000u;
constexpr DWORD OPEN_EXISTING = 3;
constexpr DWORD CREATE_ALWAYS = 2;
constexpr DWORD FILE_BEGIN = 0;
constexpr DWORD CP_UTF8 = 65001;
constexpr DWORD FSCTL_SET_SPARSE = 0x000900c4u;

namespace win32_shim_detail {

inline int fd_of(HANDLE h) {
  return static_cast<int>(reinterpret_cast<intptr_t>(h)) - 1;
}

inline std::string wide_to_utf8(const wchar_t* src, size_t n) {
  if (!src) return {};
  return adi::text::wstring_to_utf8(src, n);
}

inline size_t clamped_int(int n, size_t fallback) {
  return n < 0 ? fallback : static_cast<size_t>(n);
}

// Convert a Windows-style path to something open() accepts.
inline std::string normalize(std::string p) {
  if (p.rfind(R"(\\?\UNC\)", 0) == 0) {
    p.erase(0, 8);
    if (!p.empty()) p.insert(0, "//");
  } else if (p.rfind(R"(\\?\)", 0) == 0) {
    p.erase(0, 4);
  }
  std::replace(p.begin(), p.end(), '\\', '/');
  return p;
}

inline std::string narrow_path(const char* p) { return normalize(p ? std::string(p) : std::string()); }
inline std::string narrow_path(const wchar_t* p) {
  if (!p) return {};
  return normalize(wide_to_utf8(p, std::wcslen(p)));
}

}  // namespace win32_shim_detail

inline HANDLE CreateFileW(const char* path, DWORD access, DWORD, void*, DWORD disposition,
                          DWORD, void*) {
  const std::string p = win32_shim_detail::narrow_path(path);
  int flags = (access & GENERIC_WRITE) ? O_RDWR : O_RDONLY;
  if (disposition == CREATE_ALWAYS) flags |= O_CREAT | O_TRUNC;
  const int fd = ::open(p.c_str(), flags, 0666);
  if (fd < 0) return INVALID_HANDLE_VALUE;
  return reinterpret_cast<HANDLE>(static_cast<intptr_t>(fd + 1));
}

inline HANDLE CreateFileW(const wchar_t* path, DWORD access, DWORD share, void* sec,
                          DWORD disposition, DWORD flags, void* tmpl) {
  const std::string p = win32_shim_detail::narrow_path(path);
  return CreateFileW(p.c_str(), access, share, sec, disposition, flags, tmpl);
}

inline BOOL CloseHandle(HANDLE h) {
  if (!h || h == INVALID_HANDLE_VALUE) return 0;
  return ::close(win32_shim_detail::fd_of(h)) == 0 ? 1 : 0;
}

inline BOOL ReadFile(HANDLE h, void* buf, DWORD n, DWORD* got, void*) {
  const ssize_t r = ::read(win32_shim_detail::fd_of(h), buf, n);
  if (r < 0) {
    if (got) *got = 0;
    return 0;
  }
  if (got) *got = static_cast<DWORD>(r);
  return 1;
}

inline BOOL WriteFile(HANDLE h, const void* buf, DWORD n, DWORD* wrote, void*) {
  const ssize_t r = ::write(win32_shim_detail::fd_of(h), buf, n);
  if (r < 0) {
    if (wrote) *wrote = 0;
    return 0;
  }
  if (wrote) *wrote = static_cast<DWORD>(r);
  return 1;
}

inline BOOL SetFilePointerEx(HANDLE h, LARGE_INTEGER distance, LARGE_INTEGER* new_pos, DWORD) {
  if (distance.QuadPart < 0 ||
      static_cast<uint64_t>(distance.QuadPart) >
      static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
    return 0;
  }
  const off_t r = ::lseek(win32_shim_detail::fd_of(h), static_cast<off_t>(distance.QuadPart),
                          SEEK_SET);
  if (r < 0) return 0;
  if (new_pos) new_pos->QuadPart = static_cast<LONGLONG>(r);
  return 1;
}

inline BOOL SetEndOfFile(HANDLE h) {
  const off_t cur = ::lseek(win32_shim_detail::fd_of(h), 0, SEEK_CUR);
  if (cur < 0) return 0;
  return ::ftruncate(win32_shim_detail::fd_of(h), cur) == 0 ? 1 : 0;
}

inline BOOL GetFileSizeEx(HANDLE h, LARGE_INTEGER* size) {
  struct stat st {};
  if (::fstat(win32_shim_detail::fd_of(h), &st) != 0) return 0;
  size->QuadPart = static_cast<LONGLONG>(st.st_size);
  return 1;
}

inline BOOL CreateDirectoryW(const wchar_t* path, void*) {
  const std::string p = win32_shim_detail::narrow_path(path);
  if (p.empty()) return 0;
  return ::mkdir(p.c_str(), 0777) == 0 || errno == EEXIST ? 1 : 0;
}

inline DWORD GetFileAttributesW(const wchar_t* path) {
  const std::string p = win32_shim_detail::narrow_path(path);
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 ? 0u : INVALID_FILE_ATTRIBUTES;
}

// No-op: POSIX ftruncate() already produces sparse files.
inline BOOL DeviceIoControl(HANDLE, DWORD, void*, DWORD, void*, DWORD, DWORD*, void*) { return 1; }

// LZNT1 lives in ntdll.dll on Windows. It is only needed when extracting
// NTFS-compressed files, never for `reconstruct`, so report it unavailable.
inline HMODULE GetModuleHandleW(const wchar_t*) { return nullptr; }
inline void* GetProcAddress(HMODULE, const char*) { return nullptr; }

inline int WideCharToMultiByte(DWORD, DWORD, const wchar_t* src, int src_n, char* dst,
                               int dst_n, const char*, int*) {
  if (!src) return 0;
  const size_t n = src_n < 0 ? std::wcslen(src)
                             : win32_shim_detail::clamped_int(src_n, 0);
  const std::string out = adi::text::wstring_to_utf8(src, n);
  if (!dst) {
    return out.size() > static_cast<size_t>(INT_MAX) ? 0 : static_cast<int>(out.size());
  }
  if (dst_n <= 0 || out.size() > static_cast<size_t>(dst_n)) {
    return 0;  // Win32: 0 means "buffer too small"
  }
  if (!out.empty()) std::memcpy(dst, out.data(), out.size());
  return static_cast<int>(out.size());
}

inline int MultiByteToWideChar(DWORD, DWORD, const char* src, int src_n, wchar_t* dst,
                               int dst_n) {
  if (!src) return 0;
  const size_t n = src_n < 0 ? std::strlen(src)
                             : win32_shim_detail::clamped_int(src_n, 0);
  const std::wstring out = adi::text::utf8_to_wstring(src, n);
  if (!dst) {
    return out.size() > static_cast<size_t>(INT_MAX) ? 0 : static_cast<int>(out.size());
  }
  if (dst_n <= 0 || out.size() > static_cast<size_t>(dst_n)) {
    return 0;
  }
  for (size_t i = 0; i < out.size(); ++i) dst[i] = out[i];
  return static_cast<int>(out.size());
}
