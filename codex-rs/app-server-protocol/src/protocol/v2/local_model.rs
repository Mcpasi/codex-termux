use crate::JsonSchema;
use crate::TS;
use serde::Deserialize;
use serde::Serialize;

/// A locally installed artifact. Nothing is downloaded by these methods.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelArtifact {
    pub path: String,
    pub sha256: String,
}

/// Transient invitation returned by the helper device. Treat it as a secret.
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelPeer {
    pub endpoint: String,
    pub certificate: String,
    pub token: String,
}

impl std::fmt::Debug for LocalModelPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalModelPeer([redacted])")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelStartParams {
    pub engine: LocalModelArtifact,
    pub model: LocalModelArtifact,
    pub model_id: String,
    pub context_tokens: u32,
    pub threads: u32,
    #[ts(type = "number")]
    pub memory_budget_bytes: u64,
    /// At most nine helpers; the coordinator is the tenth device.
    pub peers: Vec<LocalModelPeer>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelStartResponse {
    pub base_url: String,
    pub model: String,
    /// Transient bearer for the loopback inference endpoint, never an account credential.
    pub bearer_token: String,
    pub plan: LocalModelPlan,
}

impl std::fmt::Debug for LocalModelStartResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalModelStartResponse([redacted])")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelWorkerStartParams {
    pub engine: LocalModelArtifact,
    /// A literal private interface address and port (zero chooses a free port).
    pub listen_address: String,
    pub threads: u32,
    #[ts(type = "number")]
    pub memory_budget_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelWorkerStartResponse {
    pub invitation: LocalModelPeer,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelStatusParams {}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export_to = "v2/")]
pub struct LocalModelStopParams {}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelStopResponse {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelStatusResponse {
    pub phase: LocalModelPhase,
    pub plan: Option<LocalModelPlan>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/", rename_all = "camelCase")]
pub enum LocalModelPhase {
    Stopped,
    Ready,
    Generating,
    Worker,
    Failed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelPlan {
    pub layers: u32,
    pub assignments: Vec<LocalModelLayerAssignment>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LocalModelLayerAssignment {
    /// Zero is this device. Other indices are one-based positions in start.peers.
    pub device_index: u32,
    pub start_layer: u32,
    pub end_layer: u32,
    #[ts(type = "number")]
    pub estimated_bytes: u64,
}
