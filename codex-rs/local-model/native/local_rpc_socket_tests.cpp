// SPDX-License-Identifier: Apache-2.0
#include "local_rpc_socket.h"
#include <cassert>
#include <cstdlib>

#ifdef NDEBUG
#error "This focused host test requires assertions."
#endif

int main() {
    char root[] = "/tmp/codex-rpc-XXXXXX";
    assert(mkdtemp(root) != nullptr);
    char canonical[4096];
    assert(realpath(root, canonical) != nullptr);
    const std::string path = std::string(canonical) + "/rpc.sock";
    using codex_local_rpc::Mode;
    using codex_local_rpc::open_socket;

    const int server = open_socket(path.c_str(), Mode::Listen);
    assert(server >= 0);
    assert(open_socket(path.c_str(), Mode::Listen) < 0);
    struct stat metadata{};
    assert(lstat(path.c_str(), &metadata) == 0);
    assert((metadata.st_mode & 0777) == 0600);
    const int client = open_socket(path.c_str(), Mode::Connect);
    assert(client >= 0);
    const int accepted = accept(server, nullptr, nullptr);
    assert(accepted >= 0);
    assert(codex_local_rpc::is_unix_socket(server));
    assert(codex_local_rpc::is_unix_socket(accepted));
    assert((fcntl(client, F_GETFD) & FD_CLOEXEC) != 0);
    assert(write(client, "rpc", 3) == 3);
    char bytes[3]{};
    assert(read(accepted, bytes, sizeof(bytes)) == 3);
    assert(std::memcmp(bytes, "rpc", 3) == 0);
    close(accepted);
    close(client);
    close(server);

    assert(chmod(canonical, 0755) == 0);
    assert(open_socket(path.c_str(), Mode::Connect) < 0);
    assert(chmod(canonical, 0700) == 0);
    assert(unlink(path.c_str()) == 0);
    assert(symlink("missing", path.c_str()) == 0);
    assert(open_socket(path.c_str(), Mode::Listen) < 0);
    assert(open_socket(path.c_str(), Mode::Connect) < 0);
    assert(unlink(path.c_str()) == 0);
    assert(open_socket("relative.sock", Mode::Listen) < 0);
    assert(open_socket((std::string(canonical) + "/" + std::string(200, 'x')).c_str(), Mode::Listen) < 0);
    assert(rmdir(canonical) == 0);
}
