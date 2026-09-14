#!/bin/sh
# Build-time only. Never invoke this script from the Android application.
set -eu
umask 077
local_model_recipe_dir=$(dirname "$0")

if [ "$#" -lt 1 ]; then
    echo 'Usage: sh build-runtime.sh /absolute/new-build-directory [CMake toolchain arguments...]' >&2
    exit 2
fi
local_model_output=$1
shift
case "$local_model_output" in
    /*) ;;
    *) echo 'The output directory must be absolute.' >&2; exit 2 ;;
esac
# Refuse to mix artifacts with a previous build or overwrite an existing directory.
mkdir "$local_model_output"
local_model_revision=5f436dddb440a288ee5611d7d1eca564a6aca9f4
local_model_source_sha=bba50b9f52805c890dc8ffd31e465379a4dc1cc9a2b23541ea6e4b0a2382ad02
local_model_archive="$local_model_output/source.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 300 \
    "https://codeload.github.com/ggml-org/llama.cpp/tar.gz/$local_model_revision" \
    --output "$local_model_archive"
if command -v sha256sum >/dev/null 2>&1; then
    local_model_hash_command=sha256sum
else
    local_model_hash_command='shasum -a 256'
fi
local_model_actual=$($local_model_hash_command "$local_model_archive")
case "$local_model_actual" in
    "$local_model_source_sha "*) ;;
    *) echo 'llama.cpp source SHA-256 mismatch.' >&2; exit 1 ;;
esac
tar -xzf "$local_model_archive" -C "$local_model_output"
local_model_source="$local_model_output/llama.cpp-$local_model_revision"
cp "$local_model_recipe_dir/native/local_rpc_socket.h" "$local_model_source/ggml/src/ggml-rpc/local_rpc_socket.h"
patch -d "$local_model_source" -p1 -F 0 < "$local_model_recipe_dir/native/llama-local-rpc.patch"
cmake -G Ninja -S "$local_model_source" -B "$local_model_output/build" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_APP=OFF \
    -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_COMMON=ON -DLLAMA_BUILD_TOOLS=ON \
    -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
    -DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_BORINGSSL=OFF -DLLAMA_BUILD_LIBRESSL=OFF \
    -DLLAMA_SUBPROCESS=OFF -DLLAMA_LLGUIDANCE=OFF \
    -DLLAMA_BUILD_COMMIT="$local_model_revision-codex-local-rpc" \
    -DGGML_RPC=ON -DGGML_RPC_RDMA=OFF -DGGML_BACKEND_DL=OFF \
    -DGGML_NATIVE=OFF -DGGML_CPU_ALL_VARIANTS=OFF -DGGML_OPENMP=OFF \
    -DGGML_BLAS=OFF -DGGML_LLAMAFILE=OFF -DGGML_METAL=OFF \
    -DGGML_CUDA=OFF -DGGML_VULKAN=OFF -DGGML_OPENCL=OFF -DGGML_SYCL=OFF \
    "$@"
cmake --build "$local_model_output/build" --target llama-server ggml-rpc-server --parallel "${LOCAL_MODEL_BUILD_JOBS:-2}"
mkdir "$local_model_output/bundle"
cp "$local_model_output/build/bin/llama-server" "$local_model_output/bundle/llama-server"
cp "$local_model_output/build/bin/ggml-rpc-server" "$local_model_output/bundle/ggml-rpc-server"
cp "$local_model_source/LICENSE" "$local_model_output/bundle/LLAMA-LICENSE"
cp "$local_model_recipe_dir/../../LICENSE" "$local_model_output/bundle/LOCAL-RPC-LICENSE"
# The notices embedded by this exact configured build, including its compiled vendor code.
sed -n '/^R"=L=(/,/)=L=",$/p' "$local_model_output/build/license.cpp" \
    | sed 's/^R"=L=(//; s/)=L=",$//' > "$local_model_output/bundle/THIRD-PARTY-NOTICES.txt"
test -s "$local_model_output/bundle/THIRD-PARTY-NOTICES.txt"
printf 'llama.cpp revision: %s\nsource SHA-256: %s\n' \
    "$local_model_revision" "$local_model_source_sha" > "$local_model_output/bundle/PROVENANCE.txt"
for local_model_extension in local_rpc_socket.h llama-local-rpc.patch; do
    local_model_extension_hash=$($local_model_hash_command "$local_model_recipe_dir/native/$local_model_extension")
    printf '%s SHA-256: %s\n' "$local_model_extension" "${local_model_extension_hash%% *}" >> "$local_model_output/bundle/PROVENANCE.txt"
done
(
    cd "$local_model_output/bundle"
    $local_model_hash_command llama-server ggml-rpc-server LLAMA-LICENSE LOCAL-RPC-LICENSE THIRD-PARTY-NOTICES.txt PROVENANCE.txt > SHA256SUMS
)
echo "Runtime candidates and hashes are in $local_model_output/bundle. Audit native dependencies before packaging."
