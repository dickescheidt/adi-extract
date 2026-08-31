#include "extract.hpp"

#include "codec.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>

namespace fs = std::filesystem;

namespace adi {
namespace {

uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

class DiskReader {
public:
    explicit DiskReader(const fs::path& p) {
        h_ = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_FLAG_RANDOM_ACCESS, nullptr);
    }
    ~DiskReader() {
        if (h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
    }
    DiskReader(const DiskReader&) = delete;
    DiskReader& operator=(const DiskReader&) = delete;

    bool ok() const { return h_ != INVALID_HANDLE_VALUE; }

    bool read(uint64_t off, void* dst, size_t n) const {
        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(off);
        if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) {
            return false;
        }
        auto* out = static_cast<uint8_t*>(dst);
        while (n) {
            DWORD got = 0;
            if (!ReadFile(h_, out, static_cast<DWORD>(std::min<size_t>(n, 1u << 24)), &got,
                          nullptr) ||
                got == 0) {
                std::memset(out, 0, n);
                return true;
            }
            out += got;
            n -= got;
        }
        return true;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

std::wstring widen(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr,
                                      nullptr);
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring sanitize(std::wstring name) {
    for (auto& c : name) {
        if (c < 0x20 || c == L'<' || c == L'>' || c == L':' || c == L'"' || c == L'/' ||
            c == L'\\' || c == L'|' || c == L'?' || c == L'*') {
            c = L'_';
        }
    }
    while (!name.empty() && (name.back() == L' ' || name.back() == L'.')) {
        name.pop_back();
    }
    if (name.empty()) {
        name = L"_";
    }
    return name;
}

std::wstring long_path(const fs::path& p) {
    std::wstring s = fs::absolute(p).wstring();
    if (s.rfind(L"\\\\?\\", 0) != 0) {
        s = L"\\\\?\\" + s;
    }
    return s;
}

bool make_dirs(const fs::path& p) {
    static std::unordered_set<std::wstring> made;
    const std::wstring full = long_path(p);
    if (made.count(full)) {
        return true;
    }
    for (size_t i = 7; i <= full.size(); ++i) {
        if (i < full.size() && full[i] != L'\\') {
            continue;
        }
        CreateDirectoryW(full.substr(0, i).c_str(), nullptr);
    }
    if (GetFileAttributesW(full.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    made.insert(full);
    return true;
}

class FileOut {
public:
    bool open(const fs::path& p) {
        close();
        h_ = CreateFileW(long_path(p).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
        return h_ != INVALID_HANDLE_VALUE;
    }
    bool write(const uint8_t* p, size_t n) {
        while (n) {
            DWORD wrote = 0;
            if (!WriteFile(h_, p, static_cast<DWORD>(std::min<size_t>(n, 1u << 24)), &wrote,
                           nullptr)) {
                return false;
            }
            p += wrote;
            n -= wrote;
        }
        return true;
    }
    void sparse() {
        DWORD ret = 0;
        DeviceIoControl(h_, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &ret, nullptr);
    }
    bool seek(uint64_t off) {
        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(off);
        return SetFilePointerEx(h_, li, nullptr, FILE_BEGIN) != 0;
    }
    void truncate(uint64_t size) {
        seek(size);
        SetEndOfFile(h_);
    }
    void close() {
        if (h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
            h_ = INVALID_HANDLE_VALUE;
        }
    }
    ~FileOut() { close(); }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

struct Run {
    uint64_t vcn = 0;
    int64_t lcn = 0;
    uint64_t count = 0;
    bool sparse = false;
};

struct Attr {
    bool present = false;
    bool resident = false;
    bool compressed = false;
    bool encrypted = false;
    uint16_t compression_unit = 0;
    uint64_t start_vcn = 0;
    uint64_t data_size = 0;
    uint64_t init_size = 0;
    std::vector<uint8_t> resident_data;
    std::vector<Run> runs;
};

bool parse_runs(const uint8_t* p, const uint8_t* end, std::vector<Run>* out) {
    int64_t lcn = 0;
    uint64_t vcn = 0;
    while (p < end && *p) {
        const uint8_t head = *p++;
        const int nlen = head & 0x0f;
        const int noff = head >> 4;
        if (nlen == 0 || nlen > 8 || noff > 8 || p + nlen + noff > end) {
            return false;
        }
        uint64_t count = 0;
        for (int i = nlen - 1; i >= 0; --i) {
            count = (count << 8) | p[i];
        }
        p += nlen;
        Run r;
        r.vcn = vcn;
        r.count = count;
        if (noff == 0) {
            r.sparse = true;
        } else {
            int64_t delta = static_cast<int8_t>(p[noff - 1]);
            for (int i = noff - 2; i >= 0; --i) {
                delta = (delta << 8) | p[i];
            }
            p += noff;
            lcn += delta;
            r.lcn = lcn;
        }
        vcn += count;
        out->push_back(r);
    }
    return true;
}

struct NtfsVolume {
    const DiskReader* disk = nullptr;
    uint64_t part_off = 0;
    uint32_t sector_size = 512;
    uint32_t cluster_size = 4096;
    uint32_t record_size = 1024;
    uint64_t mft_off = 0;
    std::vector<Run> mft_runs;

    uint64_t cluster_bytes(uint64_t lcn) const { return part_off + lcn * cluster_size; }

    bool read_runs(const std::vector<Run>& runs, uint64_t off, uint8_t* dst, size_t n) const {
        while (n) {
            const uint64_t vcn = off / cluster_size;
            const uint32_t in_cl = static_cast<uint32_t>(off % cluster_size);
            const Run* hit = nullptr;
            for (const auto& r : runs) {
                if (vcn >= r.vcn && vcn < r.vcn + r.count) {
                    hit = &r;
                    break;
                }
            }
            if (!hit) {
                std::memset(dst, 0, n);
                return true;
            }
            const uint64_t left_in_run = (hit->vcn + hit->count - vcn) * cluster_size - in_cl;
            const size_t chunk = static_cast<size_t>(std::min<uint64_t>(n, left_in_run));
            if (hit->sparse) {
                std::memset(dst, 0, chunk);
            } else if (!disk->read(cluster_bytes(uint64_t(hit->lcn) + (vcn - hit->vcn)) + in_cl,
                                  dst, chunk)) {
                return false;
            }
            dst += chunk;
            off += chunk;
            n -= chunk;
        }
        return true;
    }

    void fixup(uint8_t* rec, size_t n) const {
        const uint16_t usa = rd16(rec + 4);
        const uint16_t usc = rd16(rec + 6);
        if (usa + 2 * usc > n || usc == 0) {
            return;
        }
        for (uint16_t i = 1; i < usc; ++i) {
            const size_t at = size_t(i) * sector_size - 2;
            if (at + 2 > n) {
                break;
            }
            std::memcpy(rec + at, rec + usa + 2 * i, 2);
        }
    }

    bool read_record(uint64_t index, std::vector<uint8_t>* rec) const {
        rec->assign(record_size, 0);
        if (!read_runs(mft_runs, index * record_size, rec->data(), record_size)) {
            return false;
        }
        if (std::memcmp(rec->data(), "FILE", 4) != 0) {
            return false;
        }
        fixup(rec->data(), rec->size());
        return true;
    }
};

const uint8_t* attr_end(const std::vector<uint8_t>& rec) {
    const uint32_t used = rd32(rec.data() + 0x18);
    const size_t lim = used && used <= rec.size() ? used : rec.size();
    return rec.data() + lim;
}

Attr read_attr(const NtfsVolume& vol, const std::vector<uint8_t>& rec, uint32_t type,
               bool unnamed_only) {
    Attr out;
    const uint8_t* p = rec.data() + rd16(rec.data() + 0x14);
    const uint8_t* end = attr_end(rec);
    while (p + 16 <= end) {
        const uint32_t t = rd32(p);
        if (t == 0xffffffff) {
            break;
        }
        const uint32_t len = rd32(p + 4);
        if (len < 16 || p + len > end) {
            break;
        }
        if (t == type && (!unnamed_only || p[9] == 0)) {
            const uint16_t flags = rd16(p + 12);
            out.present = true;
            out.compressed = (flags & 0x00ff) != 0;
            out.encrypted = (flags & 0x4000) != 0;
            out.resident = p[8] == 0;
            if (out.resident) {
                const uint32_t vlen = rd32(p + 0x10);
                const uint16_t voff = rd16(p + 0x14);
                if (voff + vlen <= len) {
                    out.data_size = vlen;
                    out.init_size = vlen;
                    out.resident_data.assign(p + voff, p + voff + vlen);
                }
            } else {
                out.compression_unit = rd16(p + 0x22);
                out.start_vcn = rd64(p + 0x10);
                out.data_size = rd64(p + 0x30);
                out.init_size = rd64(p + 0x38);
                const uint16_t roff = rd16(p + 0x20);
                if (roff < len) {
                    parse_runs(p + roff, p + len, &out.runs);
                }
            }
            return out;
        }
        p += len;
    }
    (void)vol;
    return out;
}

Attr read_data_attr(const NtfsVolume& vol, const std::vector<uint8_t>& rec) {
    const Attr base = read_attr(vol, rec, 0x80, true);
    const Attr list = read_attr(vol, rec, 0x20, true);
    if (!list.present || base.resident) {
        return base;
    }
    std::vector<uint8_t> raw;
    if (list.resident) {
        raw = list.resident_data;
    } else {
        if (list.data_size > (1u << 20)) {
            return base;
        }
        raw.assign(static_cast<size_t>(list.data_size), 0);
        if (!vol.read_runs(list.runs, 0, raw.data(), raw.size())) {
            return base;
        }
    }
    const uint64_t self = rd32(rec.data() + 0x2c);
    std::set<uint64_t> holders;
    for (size_t o = 0; o + 0x1a <= raw.size();) {
        const uint32_t type = rd32(raw.data() + o);
        const uint16_t len = rd16(raw.data() + o + 4);
        if (len < 0x18 || o + len > raw.size()) {
            break;
        }
        if (type == 0x80 && raw[o + 6] == 0) {
            const uint64_t ref = rd64(raw.data() + o + 0x10) & 0x0000ffffffffffffull;
            if (ref != self) {
                holders.insert(ref);
            }
        }
        o += len;
    }
    Attr data;
    std::vector<Run> runs;
    auto take = [&](const Attr& a) {
        if (!a.present || a.resident) {
            return;
        }
        if (a.start_vcn == 0) {
            data = a;
            data.runs.clear();
        }
        for (Run r : a.runs) {
            r.vcn += a.start_vcn;
            runs.push_back(r);
        }
    };
    take(base);
    std::vector<uint8_t> ext;
    for (const uint64_t ref : holders) {
        if (vol.read_record(ref, &ext)) {
            take(read_attr(vol, ext, 0x80, true));
        }
    }
    std::sort(runs.begin(), runs.end(), [](const Run& a, const Run& b) { return a.vcn < b.vcn; });
    data.runs = std::move(runs);
    return data.present ? data : base;
}

struct NameInfo {
    std::wstring name;
    uint64_t parent = 0;
    uint8_t space = 0xff;
    bool dir = false;
    bool used = false;
};

NameInfo read_name(const std::vector<uint8_t>& rec) {
    NameInfo best;
    const uint8_t* p = rec.data() + rd16(rec.data() + 0x14);
    const uint8_t* end = attr_end(rec);
    while (p + 16 <= end) {
        const uint32_t t = rd32(p);
        if (t == 0xffffffff) {
            break;
        }
        const uint32_t len = rd32(p + 4);
        if (len < 16 || p + len > end) {
            break;
        }
        if (t == 0x30 && p[8] == 0) {
            const uint16_t voff = rd16(p + 0x14);
            const uint32_t vlen = rd32(p + 0x10);
            if (voff + vlen <= len && vlen >= 0x42) {
                const uint8_t* v = p + voff;
                const uint8_t nlen = v[0x40];
                const uint8_t space = v[0x41];
                if (0x42 + size_t(nlen) * 2 <= vlen) {
                    const uint8_t rank[4] = {1, 0, 3, 0};
                    const uint8_t r = space < 4 ? rank[space] : 4;
                    const uint8_t br = best.space < 4 ? rank[best.space] : 5;
                    if (best.space == 0xff || r < br) {
                        best.space = space;
                        best.parent = rd64(v) & 0x0000ffffffffffffull;
                        best.name.assign(reinterpret_cast<const wchar_t*>(v + 0x42), nlen);
                    }
                }
            }
        }
        p += len;
    }
    return best;
}

struct Report {
    std::map<std::string, uint64_t> counts;
    std::vector<std::string> lines;
    void add(const std::string& reason, const std::string& detail) {
        ++counts[reason];
        if (lines.size() < 5000) {
            lines.push_back(reason + ": " + detail);
        }
    }
};

bool write_ntfs_data(const NtfsVolume& vol, const Attr& data, const fs::path& out,
                     uint64_t* bytes, Report* rep) {
    FileOut f;
    if (!f.open(out)) {
        rep->add("cannot create", narrow(long_path(out)));
        return false;
    }
    if (data.resident) {
        f.write(data.resident_data.data(), data.resident_data.size());
        *bytes += data.resident_data.size();
        return true;
    }
    if (data.encrypted) {
        rep->add("EFS-encrypted, empty placeholder", narrow(out.wstring()));
        return false;
    }
    f.sparse();
    const uint64_t size = data.data_size;
    if (!data.compressed) {
        std::vector<uint8_t> buf(1u << 20);
        uint64_t at = 0;
        const uint64_t init = std::min(data.init_size ? data.init_size : size, size);
        while (at < init) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(), init - at));
            if (!vol.read_runs(data.runs, at, buf.data(), want)) {
                break;
            }
            f.write(buf.data(), want);
            at += want;
        }
        f.truncate(size);
        *bytes += size;
        return true;
    }
    const uint32_t cu_clusters = 1u << data.compression_unit;
    const uint64_t cu_bytes = uint64_t(cu_clusters) * vol.cluster_size;
    std::vector<uint8_t> in(static_cast<size_t>(cu_bytes));
    std::vector<uint8_t> out_buf(static_cast<size_t>(cu_bytes));
    uint64_t at = 0;
    bool clean = true;
    while (at < size) {
        const uint64_t vcn = at / vol.cluster_size;
        uint32_t allocated = 0;
        for (uint32_t c = 0; c < cu_clusters; ++c) {
            for (const auto& r : data.runs) {
                if (vcn + c >= r.vcn && vcn + c < r.vcn + r.count) {
                    if (!r.sparse) {
                        ++allocated;
                    }
                    break;
                }
            }
        }
        const size_t want = static_cast<size_t>(std::min<uint64_t>(cu_bytes, size - at));
        if (allocated == 0) {
            std::memset(out_buf.data(), 0, want);
            f.write(out_buf.data(), want);
        } else if (allocated == cu_clusters) {
            if (!vol.read_runs(data.runs, at, in.data(), want)) {
                clean = false;
                break;
            }
            f.write(in.data(), want);
        } else {
            const size_t csize = size_t(allocated) * vol.cluster_size;
            if (!vol.read_runs(data.runs, at, in.data(), csize)) {
                clean = false;
                break;
            }
            size_t got = 0;
            if (lznt1_decompress(in.data(), csize, out_buf.data(), size_t(cu_bytes), &got)) {
                if (got < want) {
                    std::memset(out_buf.data() + got, 0, want - got);
                }
                f.write(out_buf.data(), want);
            } else {
                std::memset(out_buf.data(), 0, want);
                f.write(out_buf.data(), want);
                clean = false;
            }
        }
        at += cu_bytes;
    }
    f.truncate(size);
    *bytes += size;
    if (!clean) {
        rep->add("partial LZNT1 decode", narrow(out.wstring()));
    }
    return true;
}

bool open_ntfs(const DiskReader& disk, uint64_t part_off, const BootSector& bs, NtfsVolume* vol,
               Attr* mft_data, std::string* why) {
    std::vector<uint8_t> boot(512);
    if (!disk.read(part_off, boot.data(), 512)) {
        *why = "boot sector unreadable";
        return false;
    }
    vol->disk = &disk;
    vol->part_off = part_off;
    vol->sector_size = bs.bytes_per_sector;
    vol->cluster_size = bs.bytes_per_sector * bs.sectors_per_cluster;
    const int8_t cpr = static_cast<int8_t>(boot[0x40]);
    vol->record_size = cpr > 0 ? uint32_t(cpr) * vol->cluster_size : uint32_t(1) << (-cpr);
    if (vol->record_size < 512 || vol->record_size > 65536) {
        vol->record_size = 1024;
    }
    std::vector<uint8_t> rec0(vol->record_size);
    if (!disk.read(part_off + bs.mft_cluster * vol->cluster_size, rec0.data(), vol->record_size) ||
        std::memcmp(rec0.data(), "FILE", 4) != 0) {
        *why = "MFT record 0 not found";
        return false;
    }
    vol->fixup(rec0.data(), rec0.size());
    *mft_data = read_attr(*vol, rec0, 0x80, true);
    if (!mft_data->present || mft_data->resident || mft_data->runs.empty()) {
        *why = "$MFT $DATA run list missing";
        return false;
    }
    vol->mft_runs = mft_data->runs;
    return true;
}

ExtractStats extract_ntfs(const DiskReader& disk, uint64_t part_off, const BootSector& bs,
                          const fs::path& root, Report* rep) {
    ExtractStats st;
    st.method = "NTFS";

    NtfsVolume vol;
    Attr mft_data;
    if (!open_ntfs(disk, part_off, bs, &vol, &mft_data, &st.notes)) {
        return st;
    }
    const uint64_t records = mft_data.data_size / vol.record_size;

    std::vector<NameInfo> names(static_cast<size_t>(records));
    std::vector<uint8_t> rec;
    for (uint64_t i = 0; i < records; ++i) {
        if (!vol.read_record(i, &rec)) {
            continue;
        }
        const uint16_t flags = rd16(rec.data() + 0x16);
        if (!(flags & 1)) {
            continue;
        }
        if (rd64(rec.data() + 0x20) != 0) {
            continue;
        }
        NameInfo ni = read_name(rec);
        if (ni.space == 0xff) {
            continue;
        }
        ni.dir = (flags & 2) != 0;
        ni.used = true;
        names[size_t(i)] = std::move(ni);
        if ((i & 0xffff) == 0) {
            std::cout << "    mft pass 1: " << i << "/" << records << "\r" << std::flush;
        }
    }

    std::vector<std::wstring> resolved(static_cast<size_t>(records));
    std::vector<uint8_t> state(static_cast<size_t>(records), 0);
    auto path_of = [&](uint64_t idx) -> const std::wstring& {
        static const std::wstring empty;
        std::vector<uint64_t> chain;
        uint64_t cur = idx;
        while (true) {
            if (cur >= records) {
                break;
            }
            if (state[size_t(cur)] == 2) {
                break;
            }
            if (cur == 5) {
                resolved[5].clear();
                state[5] = 2;
                break;
            }
            if (state[size_t(cur)] == 1 || !names[size_t(cur)].used) {
                resolved[size_t(cur)] = L"_orphan";
                state[size_t(cur)] = 2;
                break;
            }
            state[size_t(cur)] = 1;
            chain.push_back(cur);
            cur = names[size_t(cur)].parent;
        }
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            const uint64_t n = *it;
            const uint64_t par = names[size_t(n)].parent;
            const std::wstring& base =
                par < records && state[size_t(par)] == 2 ? resolved[size_t(par)] : L"_orphan";
            std::wstring p = base;
            if (!p.empty()) {
                p += L'\\';
            }
            p += sanitize(names[size_t(n)].name);
            resolved[size_t(n)] = std::move(p);
            state[size_t(n)] = 2;
        }
        return idx < records ? resolved[size_t(idx)] : empty;
    };

    for (uint64_t i = 16; i < records; ++i) {
        if (!names[size_t(i)].used || !names[size_t(i)].dir) {
            continue;
        }
        const std::wstring& rel = path_of(i);
        if (rel.empty()) {
            continue;
        }
        if (make_dirs(root / rel)) {
            ++st.dirs;
        }
    }

    for (uint64_t i = 16; i < records; ++i) {
        if (!names[size_t(i)].used || names[size_t(i)].dir) {
            continue;
        }
        if (!names[size_t(i)].name.empty() && names[size_t(i)].name[0] == L'$' &&
            names[size_t(i)].parent == 5) {
            continue;
        }
        if (!vol.read_record(i, &rec)) {
            continue;
        }
        const uint16_t flags = rd16(rec.data() + 0x16);
        if (!(flags & 1)) {
            continue;
        }
        const Attr data = read_data_attr(vol, rec);
        const std::wstring& rel = path_of(i);
        if (rel.empty()) {
            continue;
        }
        const fs::path out = root / rel;
        if (!data.present) {
            make_dirs(out.parent_path());
            FileOut f;
            if (f.open(out)) {
                ++st.files;
            }
            continue;
        }
        make_dirs(out.parent_path());
        if (write_ntfs_data(vol, data, out, &st.bytes, rep)) {
            ++st.files;
        } else {
            ++st.skipped;
        }
        if ((st.files & 0x3ff) == 0) {
            std::cout << "    files: " << st.files << ", " << (st.bytes >> 20) << " MiB\r"
                      << std::flush;
        }
    }
    std::cout << "                                                       \r";
    return st;
}

struct FatVolume {
    const DiskReader* disk = nullptr;
    uint64_t part_off = 0;
    uint32_t sector = 512;
    uint32_t spc = 1;
    uint32_t reserved = 0;
    uint32_t fats = 2;
    uint32_t fat_sectors = 0;
    uint32_t root_cluster = 2;
    uint32_t root_entries = 0;
    uint64_t data_start = 0;
    bool fat32 = true;
    std::vector<uint8_t> fat;

    uint32_t cluster_size() const { return sector * spc; }

    uint64_t cluster_off(uint32_t c) const {
        return data_start + uint64_t(c - 2) * cluster_size();
    }

    uint32_t next(uint32_t c) const {
        if (fat32) {
            const size_t at = size_t(c) * 4;
            if (at + 4 > fat.size()) {
                return 0x0fffffff;
            }
            return rd32(fat.data() + at) & 0x0fffffff;
        }
        const size_t at = size_t(c) * 2;
        if (at + 2 > fat.size()) {
            return 0xffff;
        }
        const uint16_t v = rd16(fat.data() + at);
        return v >= 0xfff8 ? 0x0fffffff : v;
    }

    bool last(uint32_t c) const { return fat32 ? c >= 0x0ffffff8 : c >= 0xfff8; }
};

std::wstring lfn_join(const std::vector<std::wstring>& parts) {
    std::wstring s;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        s += *it;
    }
    const size_t z = s.find(L'\0');
    if (z != std::wstring::npos) {
        s.resize(z);
    }
    while (!s.empty() && (s.back() == wchar_t(0xffff) || s.back() == L'\0')) {
        s.pop_back();
    }
    return s;
}

std::wstring short_name(const uint8_t* e) {
    std::wstring base, ext;
    for (int i = 0; i < 8 && e[i] != ' '; ++i) {
        base.push_back(wchar_t(e[i]));
    }
    for (int i = 8; i < 11 && e[i] != ' '; ++i) {
        ext.push_back(wchar_t(e[i]));
    }
    if (!ext.empty()) {
        base += L'.';
        base += ext;
    }
    return base;
}

void walk_fat_dir(const FatVolume& vol, uint32_t cluster, const std::vector<uint8_t>* fixed_root,
                  const fs::path& out, ExtractStats* st, Report* rep, int depth) {
    if (depth > 64) {
        return;
    }
    std::vector<uint8_t> dir;
    if (fixed_root) {
        dir = *fixed_root;
    } else {
        uint32_t c = cluster;
        while (c >= 2 && !vol.last(c) && dir.size() < (64u << 20)) {
            const size_t at = dir.size();
            dir.resize(at + vol.cluster_size());
            if (!vol.disk->read(vol.cluster_off(c), dir.data() + at, vol.cluster_size())) {
                dir.resize(at);
                break;
            }
            c = vol.next(c);
        }
    }
    std::vector<std::wstring> lfn;
    for (size_t i = 0; i + 32 <= dir.size(); i += 32) {
        const uint8_t* e = dir.data() + i;
        if (e[0] == 0x00) {
            break;
        }
        if (e[0] == 0xe5) {
            lfn.clear();
            continue;
        }
        if (e[11] == 0x0f) {
            std::wstring part;
            part.assign(reinterpret_cast<const wchar_t*>(e + 1), 5);
            part.append(reinterpret_cast<const wchar_t*>(e + 14), 6);
            part.append(reinterpret_cast<const wchar_t*>(e + 28), 2);
            lfn.push_back(std::move(part));
            continue;
        }
        if (e[11] & 0x08) {
            lfn.clear();
            continue;
        }
        std::wstring name = lfn.empty() ? short_name(e) : lfn_join(lfn);
        lfn.clear();
        if (name == L"." || name == L".." || name.empty()) {
            continue;
        }
        name = sanitize(name);
        const uint32_t start =
            (uint32_t(rd16(e + 20)) << 16) | uint32_t(rd16(e + 26));
        const uint32_t size = rd32(e + 28);
        const fs::path child = out / name;
        if (e[11] & 0x10) {
            if (make_dirs(child)) {
                ++st->dirs;
            }
            walk_fat_dir(vol, start, nullptr, child, st, rep, depth + 1);
            continue;
        }
        FileOut f;
        if (!f.open(child)) {
            rep->add("cannot create", narrow(child.wstring()));
            ++st->skipped;
            continue;
        }
        std::vector<uint8_t> buf(vol.cluster_size());
        uint64_t left = size;
        uint32_t c = start;
        while (left && c >= 2 && !vol.last(c)) {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(), left));
            if (!vol.disk->read(vol.cluster_off(c), buf.data(), want)) {
                break;
            }
            f.write(buf.data(), want);
            left -= want;
            c = vol.next(c);
        }
        if (left) {
            rep->add("short read", narrow(child.wstring()));
        }
        st->bytes += size - left;
        ++st->files;
    }
}

ExtractStats extract_fat(const DiskReader& disk, uint64_t part_off, const fs::path& root,
                         Report* rep) {
    ExtractStats st;
    st.method = "FAT";
    std::vector<uint8_t> boot(512);
    if (!disk.read(part_off, boot.data(), 512)) {
        st.notes = "boot sector unreadable";
        return st;
    }
    FatVolume vol;
    vol.disk = &disk;
    vol.part_off = part_off;
    vol.sector = rd16(boot.data() + 11);
    vol.spc = boot[13];
    vol.reserved = rd16(boot.data() + 14);
    vol.fats = boot[16];
    vol.root_entries = rd16(boot.data() + 17);
    vol.fat_sectors = rd16(boot.data() + 22);
    vol.fat32 = vol.fat_sectors == 0;
    if (vol.fat32) {
        vol.fat_sectors = rd32(boot.data() + 36);
        vol.root_cluster = rd32(boot.data() + 44);
    }
    if (!vol.sector || !vol.spc || !vol.fats || !vol.fat_sectors) {
        st.notes = "bad BPB";
        return st;
    }
    const uint64_t fat_off = part_off + uint64_t(vol.reserved) * vol.sector;
    const uint64_t root_dir_sectors =
        (uint64_t(vol.root_entries) * 32 + vol.sector - 1) / vol.sector;
    vol.data_start = fat_off + uint64_t(vol.fats) * vol.fat_sectors * vol.sector +
                     root_dir_sectors * vol.sector;
    vol.fat.resize(size_t(uint64_t(vol.fat_sectors) * vol.sector));
    if (!disk.read(fat_off, vol.fat.data(), vol.fat.size())) {
        st.notes = "FAT unreadable";
        return st;
    }
    if (vol.fats > 1) {
        std::vector<uint8_t> mirror(vol.fat.size());
        const std::vector<uint8_t> zero(vol.sector, 0);
        uint64_t healed = 0;
        if (disk.read(fat_off + vol.fat.size(), mirror.data(), mirror.size())) {
            for (size_t i = 0; i + vol.sector <= vol.fat.size(); i += vol.sector) {
                if (std::memcmp(vol.fat.data() + i, zero.data(), vol.sector) == 0 &&
                    std::memcmp(mirror.data() + i, zero.data(), vol.sector) != 0) {
                    std::memcpy(vol.fat.data() + i, mirror.data() + i, vol.sector);
                    ++healed;
                }
            }
        }
        if (healed) {
            rep->add("FAT sectors taken from the mirror copy", std::to_string(healed));
        }
    }
    make_dirs(root);
    if (vol.fat32) {
        walk_fat_dir(vol, vol.root_cluster, nullptr, root, &st, rep, 0);
    } else {
        std::vector<uint8_t> rootdir(size_t(root_dir_sectors * vol.sector));
        const uint64_t rd = fat_off + uint64_t(vol.fats) * vol.fat_sectors * vol.sector;
        disk.read(rd, rootdir.data(), rootdir.size());
        walk_fat_dir(vol, 0, &rootdir, root, &st, rep, 0);
    }
    return st;
}

void verify_ntfs(const DiskReader& disk, uint64_t part_off, const BootSector& bs,
                 const std::string& tag, VerifyResult* out) {
    NtfsVolume vol;
    Attr mft_data;
    std::string why;
    if (!open_ntfs(disk, part_off, bs, &vol, &mft_data, &why)) {
        out->lines.push_back(tag + ": " + why);
        return;
    }
    constexpr uint64_t kIndxCap = 20000;
    uint64_t mft_checks = 0;
    uint64_t mft_ok = 0;
    uint64_t first_bad = 0;
    uint64_t indx_checks = 0;
    uint64_t indx_ok = 0;
    std::vector<uint8_t> buf(1u << 20);
    std::vector<uint8_t> rec;
    std::vector<uint8_t> blk;
    for (uint64_t at = 0; at < mft_data.data_size; at += buf.size()) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(),
                                                                  mft_data.data_size - at));
        if (!vol.read_runs(mft_data.runs, at, buf.data(), want)) {
            break;
        }
        for (size_t o = 0; o + vol.record_size <= want; o += vol.record_size) {
            const uint8_t* r = buf.data() + o;
            if (std::memcmp(r, "FILE", 4) != 0) {
                continue;
            }
            const uint64_t idx = (at + o) / vol.record_size;
            ++mft_checks;
            if (rd32(r + 0x2c) == idx) {
                ++mft_ok;
            } else if (!first_bad) {
                first_bad = idx;
            }
            const uint16_t flags = rd16(r + 0x16);
            if (!(flags & 1) || !(flags & 2) || indx_checks >= kIndxCap) {
                continue;
            }
            rec.assign(r, r + vol.record_size);
            vol.fixup(rec.data(), rec.size());
            const Attr root = read_attr(vol, rec, 0x90, false);
            const Attr alloc = read_attr(vol, rec, 0xa0, false);
            if (!alloc.present || alloc.resident || alloc.runs.empty()) {
                continue;
            }
            uint32_t blk_size = 4096;
            if (root.present && root.resident && root.resident_data.size() >= 16) {
                const uint32_t v = rd32(root.resident_data.data() + 8);
                if (v >= 512 && v <= 65536) {
                    blk_size = v;
                }
            }
            blk.assign(blk_size, 0);
            for (const auto& run : alloc.runs) {
                if (run.sparse) {
                    continue;
                }
                for (uint64_t c = 0; c < run.count && indx_checks < kIndxCap; ++c) {
                    const uint64_t voff = (run.vcn + c) * vol.cluster_size;
                    if (voff % blk_size) {
                        continue;
                    }
                    if (!vol.read_runs(alloc.runs, voff, blk.data(), blk_size)) {
                        break;
                    }
                    if (std::memcmp(blk.data(), "INDX", 4) != 0) {
                        continue;
                    }
                    ++indx_checks;
                    if (rd64(blk.data() + 0x10) == voff / blk_size) {
                        ++indx_ok;
                    }
                }
            }
        }
    }
    out->checks += mft_checks + indx_checks;
    out->ok += mft_ok + indx_ok;
    std::string line = tag + ": MFT records " + std::to_string(mft_ok) + "/" +
                       std::to_string(mft_checks) + " at their own number";
    if (mft_ok != mft_checks) {
        line += " (first wrong: " + std::to_string(first_bad) + ")";
    }
    line += ", INDX buffers " + std::to_string(indx_ok) + "/" + std::to_string(indx_checks) +
            " at their own VCN";
    out->lines.push_back(line);
}

void verify_fat(const DiskReader& disk, uint64_t part_off, const std::string& tag,
                VerifyResult* out) {
    std::vector<uint8_t> boot(512);
    if (!disk.read(part_off, boot.data(), 512)) {
        out->lines.push_back(tag + ": boot sector unreadable");
        return;
    }
    const uint32_t sector = rd16(boot.data() + 11);
    const uint32_t reserved = rd16(boot.data() + 14);
    const uint32_t fats = boot[16];
    uint64_t fat_sectors = rd16(boot.data() + 22);
    if (fat_sectors == 0) {
        fat_sectors = rd32(boot.data() + 36);
    }
    if (!sector || !reserved || fats < 2 || !fat_sectors) {
        out->lines.push_back(tag + ": no second FAT to compare");
        return;
    }
    const size_t n = static_cast<size_t>(fat_sectors * sector);
    std::vector<uint8_t> a(n);
    std::vector<uint8_t> b(n);
    const uint64_t fat_off = part_off + uint64_t(reserved) * sector;
    if (!disk.read(fat_off, a.data(), n) || !disk.read(fat_off + n, b.data(), n)) {
        out->lines.push_back(tag + ": FAT unreadable");
        return;
    }
    const std::vector<uint8_t> zero(sector, 0);
    size_t same = 0;
    size_t both = 0;
    size_t absent = 0;
    for (size_t i = 0; i + sector <= n; i += sector) {
        const bool ha = std::memcmp(a.data() + i, zero.data(), sector) != 0;
        const bool hb = std::memcmp(b.data() + i, zero.data(), sector) != 0;
        if (!ha || !hb) {
            absent += (ha != hb) ? 1 : 0;
            continue;
        }
        ++both;
        if (std::memcmp(a.data() + i, b.data() + i, sector) == 0) {
            ++same;
        }
    }
    out->checks += both;
    out->ok += same;
    out->lines.push_back(tag + ": FAT copies agree on " + std::to_string(same) + "/" +
                         std::to_string(both) + " sectors held by both, " +
                         std::to_string(absent) + " held by one");
}

}  // namespace

VerifyResult verify_image(const fs::path& img_path, const DiskGeometry& geo) {
    VerifyResult out;
    DiskReader disk(img_path);
    if (!disk.ok()) {
        out.lines.push_back("cannot open " + img_path.string());
        return out;
    }
    for (const auto& p : geo.partitions) {
        const uint64_t off = p.first_lba * geo.sector_size;
        std::vector<uint8_t> boot(512);
        if (!disk.read(off, boot.data(), 512)) {
            continue;
        }
        BootSector bs;
        if (!parse_boot_sector(boot.data(), boot.size(), &bs)) {
            continue;
        }
        const std::string tag = "p" + std::to_string(p.index) + " " + bs.fs;
        if (bs.fs == "NTFS") {
            verify_ntfs(disk, off, bs, tag, &out);
        } else if (bs.fs.rfind("FAT", 0) == 0) {
            verify_fat(disk, off, tag, &out);
        }
    }
    return out;
}

ExtractStats extract_from_image(const fs::path& img_path, const DiskGeometry& geo,
                                const fs::path& out_dir) {
    ExtractStats total;
    DiskReader disk(img_path);
    if (!disk.ok()) {
        total.notes = "cannot open " + img_path.string();
        return total;
    }
    Report rep;
    std::vector<Partition> parts = geo.partitions;
    if (parts.empty()) {
        Partition p;
        p.index = 0;
        p.first_lba = 0;
        parts.push_back(p);
    }
    for (const auto& p : parts) {
        const uint64_t off = p.first_lba * geo.sector_size;
        std::vector<uint8_t> boot(512);
        if (!disk.read(off, boot.data(), 512)) {
            continue;
        }
        BootSector bs;
        if (!parse_boot_sector(boot.data(), boot.size(), &bs)) {
            rep.add("no recognisable boot sector",
                    "partition " + std::to_string(p.index) + " at LBA " +
                        std::to_string(p.first_lba));
            continue;
        }
        const std::string tag = "p" + std::to_string(p.index) + "_" + bs.fs;
        const fs::path root = out_dir / narrow(sanitize(widen(tag)));
        make_dirs(root);
        std::cout << "  " << tag << " (" << bs.fs << ")\n" << std::flush;

        ExtractStats one;
        if (bs.fs == "NTFS") {
            one = extract_ntfs(disk, off, bs, root, &rep);
        } else if (bs.fs.rfind("FAT", 0) == 0) {
            one = extract_fat(disk, off, root, &rep);
        } else {
            rep.add("unsupported filesystem",
                    bs.fs + " on partition " + std::to_string(p.index));
            continue;
        }
        std::cout << "    " << one.files << " files, " << one.dirs << " dirs, "
                  << (one.bytes >> 20) << " MiB";
        if (!one.notes.empty()) {
            std::cout << " (" << one.notes << ")";
        }
        std::cout << "\n";
        total.files += one.files;
        total.dirs += one.dirs;
        total.bytes += one.bytes;
        total.skipped += one.skipped;
        ++total.partitions;
        if (total.method.find(one.method) == std::string::npos) {
            total.method += (total.method.empty() ? "" : "+") + one.method;
        }
    }
    std::ofstream out(out_dir / "report.txt", std::ios::trunc);
    out << "partitions processed: " << total.partitions << "\n"
        << "files: " << total.files << "\ndirs: " << total.dirs << "\nbytes: " << total.bytes
        << "\nskipped: " << total.skipped << "\n";
    if (!rep.counts.empty()) {
        out << "\nby reason (all occurrences):\n";
        for (const auto& kv : rep.counts) {
            out << "  " << kv.second << "  " << kv.first << "\n";
        }
    }
    out << "\nsample (first " << rep.lines.size() << "):\n";
    for (const auto& l : rep.lines) {
        out << l << "\n";
    }
    return total;
}

}  // namespace adi
