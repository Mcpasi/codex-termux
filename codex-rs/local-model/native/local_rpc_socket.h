// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef _WIN32
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace codex_local_rpc {

enum class Mode { Listen, Connect };

// The Rust owner creates and retains a canonical, owner-only directory. Never unlink or
// replace an existing entry here, and never fall back to TCP after Unix validation fails.
inline int open_socket(const char * path, Mode mode) {
    sockaddr_un address{};
    if (path == nullptr || path[0] != '/' || std::strlen(path) >= sizeof(address.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    const std::string value(path);
    const auto separator = value.rfind('/');
    const std::string parent = value.substr(0, separator);
    struct stat info{};
    if (parent.empty() || lstat(parent.c_str(), &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 077) != 0) {
        errno = EACCES;
        return -1;
    }
    if (mode == Mode::Connect &&
        (lstat(path, &info) != 0 || !S_ISSOCK(info.st_mode) || info.st_uid != geteuid() ||
         (info.st_mode & 077) != 0)) {
        errno = EACCES;
        return -1;
    }
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    const int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        const int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path, value.size() + 1);
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + value.size() + 1);
    int result;
    if (mode == Mode::Listen) {
        result = bind(fd, reinterpret_cast<const sockaddr *>(&address), size);
        if (result == 0) {
            result = chmod(path, 0600);
        }
        if (result == 0) {
            result = listen(fd, 16);
        }
    } else {
        result = connect(fd, reinterpret_cast<const sockaddr *>(&address), size);
    }
    if (result != 0) {
        const int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

inline bool is_unix_socket(int fd) {
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    return getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) == 0 &&
           address.ss_family == AF_UNIX;
}

} // namespace codex_local_rpc
#endif
