# Local models and paired Android helpers

This experimental module runs an installed GGUF model locally and can distribute its transformer layers across **one coordinator and up to nine helpers**. The coordinator exposes a private inference provider for the existing Codex agent loop. The same app-server JSONL interface is available to AGENTCODI; no Android UI code or APK is changed here.

The Rust crate owns admission, memory planning, authenticated transport and child lifetime. A separately installed, SHA-256-verified C++ llama.cpp runtime performs the computation. The host owns model and executable installation. This module does not write model files, provider credentials, conversations or pairing invitations to storage.

## Current scope

- CPU inference, including the CPU kernels and GGUF quantizations supported by the installed llama.cpp build.
- Native device pooling on Android, Linux and macOS through private Unix sockets. Windows can use a single local model; creating a native helper or pool there fails explicitly. Pure planning, protocol and TLS tests remain portable.
- GGUF v3 in one regular file, up to 64 GiB, with `llama`, `qwen2`, `qwen3`, `gemma`, `gemma2`, `gemma3`, `phi3` or `mistral` architecture metadata. Other architectures, including recurrent and hybrid models, need a separate memory estimator.
- A context of 256–32,768 tokens, 1–64 CPU threads per device, and an explicit 512 MiB–64 GiB memory budget per device. Budgets include an overhead reserve; they are not a guarantee that every valid model fits.
- Manual pairing using literal private IPv4/IPv6 addresses. Existing paired helpers may become available or unavailable between requests. There is no discovery broadcast, Internet rendezvous, Bluetooth implementation or automatic model download.
- Model weights are loaded from the coordinator's verified file and sent through the encrypted RPC channels. Helpers do not need a complete copy or a filesystem path supplied by the coordinator.
- One generation at a time. A helper admits one coordinator lease at a time, including that coordinator's multiple native RPC channels.

More devices primarily increase available model memory. Sequential token decoding still depends on the slowest useful stages and network transfers; this is not a claim of linear speedup or a benchmarked “supercomputer”. The planner prefers a local fit, otherwise enough memory on as few helpers as possible, with measured connection latency as a tie-breaker. It is not a compute-throughput optimizer.

## Runtime provenance and installation

The adapter targets llama.cpp revision `5f436dddb440a288ee5611d7d1eca564a6aca9f4` with the included private Unix RPC transport extension. The upstream source archive SHA-256 is `bba50b9f52805c890dc8ffd31e465379a4dc1cc9a2b23541ea6e4b0a2382ad02`. The recipe also records the extension header and patch hashes in its provenance. Unmodified upstream binaries cannot provide this module's native device pool.

`build-runtime.sh` is a **build-time** recipe for the required native artifacts. It applies the bounded transport patch without fuzzy matching, builds CPU-only `llama-server` and `ggml-rpc-server`, and emits artifact hashes, provenance, the build's embedded notices and the Apache-2.0 license for the local RPC extension. It disables upstream UI asset downloads, HTTPS libraries, native subprocess tools, RDMA, dynamically loaded backends and optional GPU/BLAS/OpenMP dependencies.

The build host needs a C++17 compiler, CMake, Ninja, curl, tar, patch and either sha256sum or shasum. Choose a new absolute output directory; the recipe refuses to reuse an existing directory.

```sh
sh codex-rs/local-model/build-runtime.sh /tmp/local-model-native
```

For Android, pass the NDK CMake toolchain, `-DANDROID_ABI=arm64-v8a`, the application's supported API level and `-DANDROID_STL=c++_static`. Do not change Codex's Rust linker, sandbox, V8/JIT, code-mode host or release flags to build these separate inference artifacts. This script does not modify those build paths.

The output is a **candidate runtime**, not an audited APK payload. Before incorporating it into AGENTCODI, inspect the exact native dependency graph, retain the applicable permissive notices for every shipped object, verify signing/alignment/package gates, and pin the final APK artifacts. Keep inference executables in the canonical private native-library area; never install them into the workspace or `CODEX_HOME` at runtime. The source archive and build directories are not APK content. Nothing in this change replaces the currently pinned Codex artifact.

Supply canonical absolute artifact paths and their exact SHA-256 values. Links, group/other-writable artifacts, replacement and metadata changes fail validation. On Linux/Android, the child uses inherited verified file descriptors for the executable and model. Regular file handles stay open while the runtime is active. Model files must remain unchanged for the session; do not edit or replace a loaded model.

## App-server contract

Use the existing initialized connection with `experimentalApi: true`. The four v2 methods are:

| Method | Purpose | Response |
| --- | --- | --- |
| `localModel/workerStart` | Start this device as a CPU helper | Transient invitation |
| `localModel/start` | Verify a model, plan layers and start the coordinator | Provider URL, bearer, model and plan |
| `localModel/status` | Read content-free role and current plan | `stopped`, `ready`, `generating`, `worker` or `failed` |
| `localModel/stop` | Cancel this connection's role, including an in-progress start | Empty object |

`start` and `workerStart` are mutually exclusive. The first local-model request claims the role for that connection. Disconnect tears it down and releases ownership; another connection cannot read or control it meanwhile. A client should use a finite timeout of up to 930 seconds for a large model start (hashing and loading), and 30 seconds for stop. Stop cancels an in-progress start and waits for child shutdown within finite deadlines. Artifact hashing is bounded in size; native loading has a 300-second deadline. No action is silently replayed after a failure.

On each helper call `localModel/workerStart`:

```json
{
  "engine": {"path": "<canonical ggml-rpc-server path>", "sha256": "<64 hex digits>"},
  "listenAddress": "192.168.1.21:0",
  "threads": 2,
  "memoryBudgetBytes": 2147483648
}
```

The returned `invitation` contains `endpoint`, `certificate` (base64 DER) and `token` (base64 pairing secret). Transfer it through an explicit trusted pairing flow. It grants access to computation on that helper, and is valid only until that helper stops. Do not include invitations in logs, diagnostics, preferences, conversation history or model context.

On the coordinator call `localModel/start`:

```json
{
  "engine": {"path": "<canonical llama-server path>", "sha256": "<64 hex digits>"},
  "model": {"path": "<canonical model.gguf path>", "sha256": "<64 hex digits>"},
  "modelId": "my-local-model",
  "contextTokens": 4096,
  "threads": 2,
  "memoryBudgetBytes": 2147483648,
  "peers": []
}
```

For pooled inference, put up to nine helper invitations in `peers`. The response includes `baseUrl`, `bearerToken`, `model` and `plan`. Assignment zero represents the coordinator; other `deviceIndex` values are one-based positions in the supplied `peers` array. Layer ranges are half-open. The coordinator always owns tokenizer/output/runtime overhead, even if it owns no transformer layers.

Create the Codex thread through ordinary `thread/start`, selecting a custom `modelProvider` such as `local-pool` and the returned model. Its transient `config` override for `model_providers.local-pool` should contain:

```json
{
  "name": "Local device pool",
  "base_url": "<returned baseUrl>",
  "wire_api": "responses",
  "experimental_bearer_token": "<returned bearerToken>",
  "requires_openai_auth": false,
  "supports_websockets": false,
  "request_max_retries": 0,
  "stream_max_retries": 0,
  "stream_idle_timeout_ms": 600000
}
```

Also set the thread's `model_context_window` to the chosen context and `web_search` to `"disabled"`, because llama.cpp does not implement OpenAI-hosted search. Choose enough context for Codex's instructions, tool descriptions, input and output together; a small context that can load a model may still be too small for an agent turn. The provider accepts bounded full-context `POST /v1/responses` requests and rejects `previous_response_id`; it does not expose a model catalogue or a remote-control API.

The adapter translates function tools, namespaces and custom tools into llama.cpp function schemas, then restores the original Codex names, namespaces and custom inputs in the returned events. Custom tools use one JSON string named `input`; their original format description remains visible to the model, but grammar-constrained decoding of that string is not retained. Custom input becomes available at item completion. Execution, argument validation, approvals and JIT evaluation remain in the existing Codex tool path. Tool-call quality still depends on the model's chat template. Hosted tools, image/audio/file content and encrypted-only reasoning from a cloud-model history are rejected. Start a new local-model thread when existing history contains those unsupported items. Local model selection confers no additional tool or filesystem permissions.

AGENTCODI should manage these methods through its existing service/JNI/app-server path. It needs its own native model/pairing UI, transient provider selection, bounded model-file import and artifact packaging before this becomes a usable APK feature. It must not connect its UI to the private inference HTTP endpoint, expose helper pairing values to the model, or use these endpoints as execution/workspace roots. This change deliberately supplies the inheritable runtime/API side.

## Replanning, bounds and failure behavior

Before each inference request the coordinator probes its paired helpers in parallel, with five-second connection/telemetry deadlines. On Linux/Android, capacity uses `MemAvailable`, the explicit budget and the existing inference child's RSS when planning replacement. Other host platforms use the explicit budget; native host telemetry adapters can be added independently.

GGUF tensor extents determine layer weights. KV estimates use at least full embedding K+V at f16, account for wider explicit attention-head dimensions and cache padding, and include runtime reserves. Replanning occurs only before a request and replaces the entire native model/KV session when needed. Hysteresis avoids reloading for small memory fluctuations. There is no migration in the middle of a token or active response. An expired idle helper channel may be replaced for the next explicit request; a failed active response requires an explicit stop/restart and never retries that prompt.

The API gateway accepts one authenticated streaming request at a time, at most 8 MiB of request data, 256 tools, 4,096 history items, 1 MiB per SSE line and 16 MiB of response data, with separate size checks after translation. Request-body receipt has a 15-second deadline, response streaming a 90-second idle deadline and a 30-minute total deadline. A complete successful terminal Responses event is required before the session can be reused; the client need not wait for HTTP EOF. A bounded producer keeps disconnect and cancellation independent of downstream backpressure. Device channels use 64 KiB buffers, five-second authenticated handshakes, 90-second I/O deadlines, at most 128 GiB transferred per direction and a one-hour lifetime. Admission is bounded to 16 helper connections and eight local RPC channels per helper. Linux/Android helper RSS and coordinator RSS during requests are sampled every 250 ms; coordinator startup also checks RSS while polling health. An over-budget engine is stopped. These monitors cannot prevent a transient overshoot; virtual-address limits are deliberately avoided because Android allocators reserve large address ranges.

TLS authenticates the helper certificate pinned in the invitation, and a random 256-bit pairing secret authenticates the coordinator before native RPC bytes are accepted. Wildcard/public/DNS endpoints and redirects are rejected. Both native RPC legs use private filesystem Unix sockets, with owner-only directories and sockets; they never open a raw loopback or LAN RPC port. The native extension rejects existing entries, symlinks and shared socket directories, and does not fall back to TCP after a Unix failure.

The app-server creates these transient directories beside `CODEX_HOME`, outside that directory and outside AGENTCODI's sibling workspace and tool temporary directory. It does not change `TMPDIR` or the existing sandbox/JIT environment. A host embedding `LocalModelRuntime` directly must supply a canonical private parent outside every permitted tool/workspace root. Socket paths are limited to fewer than 100 bytes for portable Unix addressing. The TLS listener is the only device-facing compute endpoint; the bearer-protected loopback HTTP provider is internal to Codex inference. Devices and their paired coordinators still need to be trusted: upstream native RPC is experimental, and transport authentication does not make arbitrary native compute graphs a hardened multi-tenant service.

## Verification handoff

Tests and builds were intentionally not run for this change. `just fmt` was run; its unrelated formatting edits were removed, including edits to the existing Android sandbox and JIT helper files. Those paths retain their original contents.

The added Rust tests cover GGUF bounds, hash/replacement/link validation, layer coverage through ten devices, native split rounding, exhausted/lost capacity, certificate pinning and pairing authentication, bidirectional relay, exclusive helper leases, private socket cleanup, tool/history translation, bounded stream completion and cancellation, stateless request validation and app-server lifecycle/connection ownership. A focused C++ host test exercises the private native socket extension. These tests require no downloaded model, real GPU, Android device or cloud credentials. The dedicated GitHub Actions workflow is configured for these host and app-server/protocol checks; it has not been run. Device performance, thermals, actual model inference, native artifact compatibility and Android lifecycle behavior remain unverified until you test them.

Use the repository's usual checks, including:

```sh
just test -p codex-local-model
just test -p codex-app-server --test all -E 'test(local_model_)'
just test -p codex-app-server --lib -E 'test(local_model_)'
just test -p codex-app-server-protocol
just write-app-server-schema --experimental
just bazel-lock-update
```

The experimental precomputed API archive is updated without compiling a schema generator. Regenerate it with the normal tool in your build environment and review any drift before merging. Cargo metadata was read with `--locked --no-deps`; no dependencies were upgraded. Bazel lock regeneration was not performed in this Android workspace and remains part of the build handoff. Run your existing Android sandbox and JIT gates alongside the full Codex checks; the new tests do not replace them. No commits are created by this workflow.

Primary references: [llama.cpp RPC](https://github.com/ggml-org/llama.cpp/blob/5f436dddb440a288ee5611d7d1eca564a6aca9f4/tools/rpc/README.md), [llama.cpp Responses server](https://github.com/ggml-org/llama.cpp/blob/5f436dddb440a288ee5611d7d1eca564a6aca9f4/tools/server/README.md), [upstream security scope](https://github.com/ggml-org/llama.cpp/blob/5f436dddb440a288ee5611d7d1eca564a6aca9f4/SECURITY.md).
