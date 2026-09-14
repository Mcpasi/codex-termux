use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use axum::body::Bytes;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq)]
enum ToolKind {
    Function,
    Custom,
}

struct Binding {
    name: String,
    namespace: Option<String>,
    kind: ToolKind,
}

/// Translate only wire formats. Execution and permission checks remain owned by Codex.
#[derive(Default)]
pub(crate) struct Adapter {
    bindings: BTreeMap<String, Binding>,
}

impl Adapter {
    pub fn request(mut request: Value) -> Result<(Bytes, Self)> {
        let mut adapter = Self::default();
        if let Some(tools) = request.get_mut("tools") {
            let original = tools
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid tools"))?;
            ensure!(original.len() <= 256, "too many tools");
            let mut flattened = Vec::new();
            for tool in original {
                if tool.get("type").and_then(Value::as_str) == Some("namespace") {
                    let namespace = bounded_name(tool, "name")?;
                    let nested = tool
                        .get("tools")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow::anyhow!("namespace tools missing"))?;
                    for child in nested {
                        flattened.push(adapter.tool(child.clone(), Some(namespace))?);
                    }
                } else {
                    flattened.push(adapter.tool(tool.clone(), /*namespace*/ None)?);
                }
            }
            *tools = Value::Array(flattened);
        }
        ensure!(
            request
                .get("tool_choice")
                .is_none_or(|choice| matches!(choice.as_str(), Some("auto" | "none" | "required"))),
            "unsupported tool choice"
        );
        let input = request
            .get_mut("input")
            .ok_or_else(|| anyhow::anyhow!("input missing"))?;
        if let Some(items) = input.as_array_mut() {
            ensure!(items.len() <= 4096, "too many input items");
            for item in items {
                let kind = item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("message");
                match kind {
                    "function_call" | "custom_tool_call" => {
                        let custom = kind == "custom_tool_call";
                        let name = bounded_name(item, "name")?;
                        let namespace = item
                            .get("namespace")
                            .filter(|v| !v.is_null())
                            .map(|_| bounded_name(item, "namespace"))
                            .transpose()?;
                        let alias = alias(name, namespace);
                        let object = item
                            .as_object_mut()
                            .ok_or_else(|| anyhow::anyhow!("invalid call"))?;
                        object.insert("name".into(), json!(alias));
                        object.remove("namespace");
                        if custom {
                            let input = object
                                .remove("input")
                                .filter(Value::is_string)
                                .ok_or_else(|| anyhow::anyhow!("custom input missing"))?;
                            object.insert("type".into(), json!("function_call"));
                            object.insert(
                                "arguments".into(),
                                json!(serde_json::to_string(&json!({"input": input}))?),
                            );
                        }
                    }
                    "custom_tool_call_output" | "function_call_output" => {
                        text_parts(item.get("output"))?;
                        item["type"] = json!("function_call_output");
                    }
                    "message" => text_parts(item.get("content"))?,
                    "reasoning" => {
                        // llama.cpp requires visible reasoning text; encrypted cloud state cannot migrate.
                        ensure!(
                            item.get("content")
                                .and_then(Value::as_array)
                                .is_some_and(|v| !v.is_empty()),
                            "reasoning content cannot be migrated to this local model"
                        );
                    }
                    _ => bail!("unsupported local model input item"),
                }
            }
        } else {
            ensure!(input.is_string(), "invalid input");
        }
        let bytes = serde_json::to_vec(&request)?;
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "adapted request exceeds its bound"
        );
        Ok((Bytes::from(bytes), adapter))
    }

    fn tool(&mut self, mut tool: Value, namespace: Option<&str>) -> Result<Value> {
        ensure!(self.bindings.len() < 256, "too many tools");
        let name = bounded_name(&tool, "name")?.to_owned();
        let kind = match tool.get("type").and_then(Value::as_str) {
            Some("function") => ToolKind::Function,
            Some("custom") => ToolKind::Custom,
            _ => bail!("hosted or nested tool type is unsupported by the local engine"),
        };
        let wire_name = alias(&name, namespace);
        let qualified = namespace.map_or_else(|| name.clone(), |space| format!("{space}.{name}"));
        let mut description = tool
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if namespace.is_some() {
            description = format!("{qualified}\n{description}");
        }
        if kind == ToolKind::Custom {
            if let Some(format) = tool.get("format") {
                description.push_str("\nInput format: ");
                description.push_str(&serde_json::to_string(format)?);
            }
            tool = json!({
                "type": "function",
                "strict": true,
                "parameters": {
                    "type": "object",
                    "properties": {"input": {"type": "string"}},
                    "required": ["input"],
                    "additionalProperties": false
                }
            });
        }
        tool["name"] = json!(wire_name);
        tool["description"] = json!(description);
        ensure!(
            self.bindings
                .insert(
                    wire_name,
                    Binding {
                        name,
                        namespace: namespace.map(str::to_owned),
                        kind
                    }
                )
                .is_none(),
            "duplicate tool alias"
        );
        Ok(tool)
    }

    pub fn event(&self, event: &mut Value) -> Result<()> {
        let added = event.get("type").and_then(Value::as_str) == Some("response.output_item.added");
        if let Some(item) = event.get_mut("item") {
            self.output(
                item,
                if added {
                    OutputStage::Added
                } else {
                    OutputStage::Complete
                },
            )?;
        }
        if let Some(output) = event
            .pointer_mut("/response/output")
            .and_then(Value::as_array_mut)
        {
            ensure!(output.len() <= 256, "too many output items");
            for item in output {
                self.output(item, OutputStage::Complete)?;
            }
        }
        Ok(())
    }

    fn output(&self, item: &mut Value, stage: OutputStage) -> Result<()> {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            return Ok(());
        }
        let wire_name = bounded_name(item, "name")?;
        let binding = self
            .bindings
            .get(wire_name)
            .ok_or_else(|| anyhow::anyhow!("unknown local model tool"))?;
        let object = item
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid tool output"))?;
        object.insert("name".into(), json!(binding.name));
        if let Some(namespace) = &binding.namespace {
            object.insert("namespace".into(), json!(namespace));
        } else {
            object.remove("namespace");
        }
        if binding.kind == ToolKind::Custom {
            let arguments = object
                .remove("arguments")
                .ok_or_else(|| anyhow::anyhow!("custom arguments missing"))?;
            let arguments = arguments
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid custom arguments"))?;
            let input = match stage {
                OutputStage::Added => Value::String(String::new()),
                OutputStage::Complete => {
                    let parsed: Value = serde_json::from_str(arguments)?;
                    ensure!(
                        parsed.as_object().is_some_and(|v| v.len() == 1),
                        "invalid custom input envelope"
                    );
                    parsed
                        .get("input")
                        .filter(|value| value.is_string())
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("custom input missing"))?
                }
            };
            object.insert("type".into(), json!("custom_tool_call"));
            object.insert("input".into(), input);
        }
        Ok(())
    }
}

enum OutputStage {
    Added,
    Complete,
}

fn bounded_name<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let name = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("tool name missing"))?;
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "invalid tool name"
    );
    Ok(name)
}

fn alias(name: &str, namespace: Option<&str>) -> String {
    match namespace {
        None => name.to_owned(),
        Some(namespace) => {
            let hash = format!("{:x}", Sha256::digest(format!("{namespace}\0{name}")));
            let prefix = &name[..name.len().min(24)];
            let suffix = &hash[..32];
            format!("{prefix}_{suffix}")
        }
    }
}

fn text_parts(value: Option<&Value>) -> Result<()> {
    let value = value.ok_or_else(|| anyhow::anyhow!("text content missing"))?;
    if value.is_string() {
        return Ok(());
    }
    let parts = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid text content"))?;
    ensure!(
        parts.len() <= 4096
            && parts.iter().all(|part| matches!(
                part.get("type").and_then(Value::as_str),
                Some("input_text" | "output_text" | "refusal")
            )),
        "this local model supports text content only"
    );
    Ok(())
}

#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
