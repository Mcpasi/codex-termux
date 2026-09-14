use super::*;
use pretty_assertions::assert_eq;

#[test]
fn namespaced_function_calls_round_trip_with_history() -> Result<()> {
    let (request, adapter) = Adapter::request(json!({
        "input": [{"type":"function_call", "name":"inspect", "namespace":"workspace", "call_id":"call_1", "arguments":"{}"}],
        "tools": [{"type":"namespace", "name":"workspace", "tools":[{"type":"function", "name":"inspect", "description":"Read directory entries", "parameters":{"type":"object"}}]}]
    }))?;
    let request: Value = serde_json::from_slice(&request)?;
    assert_eq!(request["input"][0]["name"], request["tools"][0]["name"]);
    assert!(request["input"][0].get("namespace").is_none());
    let mut event = json!({"type":"response.output_item.done", "item":{
        "type":"function_call", "name":request["tools"][0]["name"], "arguments":"{}", "call_id":"call_2"
    }});
    adapter.event(&mut event)?;
    assert_eq!(
        event,
        json!({"type":"response.output_item.done", "item":{
            "type":"function_call", "name":"inspect", "namespace":"workspace", "arguments":"{}", "call_id":"call_2"
        }})
    );
    Ok(())
}

#[test]
fn custom_input_is_wrapped_for_inference_and_restored_for_codex_execution() -> Result<()> {
    let (request, adapter) = Adapter::request(json!({
        "input": [
            {"type":"custom_tool_call", "name":"exec", "call_id":"call_1", "input":"return 2 + 2;"},
            {"type":"custom_tool_call_output", "call_id":"call_1", "output":"4"}
        ],
        "tools": [{"type":"custom", "name":"exec", "description":"Run code", "format":{"type":"text"}}]
    }))?;
    let request: Value = serde_json::from_slice(&request)?;
    assert_eq!(
        request["input"],
        json!([
            {"type":"function_call", "name":"exec", "call_id":"call_1", "arguments":"{\"input\":\"return 2 + 2;\"}"},
            {"type":"function_call_output", "call_id":"call_1", "output":"4"}
        ])
    );
    assert_eq!(
        request["tools"][0]["parameters"],
        json!({
            "type":"object", "properties":{"input":{"type":"string"}}, "required":["input"], "additionalProperties":false
        })
    );
    let mut event = json!({"type":"response.output_item.done", "item":{
        "type":"function_call", "name":"exec", "arguments":"{\"input\":\"return 3 + 3;\"}", "call_id":"call_2"
    }});
    adapter.event(&mut event)?;
    assert_eq!(
        event,
        json!({"type":"response.output_item.done", "item":{
            "type":"custom_tool_call", "name":"exec", "input":"return 3 + 3;", "call_id":"call_2"
        }})
    );
    let mut invalid = json!({"item":{"type":"function_call", "name":"exec", "arguments":"{\"input\":\"x\",\"extra\":true}"}});
    assert!(adapter.event(&mut invalid).is_err());
    Ok(())
}

#[test]
fn incompatible_media_hosted_tools_and_unknown_output_tools_fail_closed() {
    for request in [
        json!({"input":[{"role":"user", "content":[{"type":"input_image", "image_url":"https://example.invalid/image"}]}]}),
        json!({"input":[], "tools":[{"type":"web_search", "name":"search"}]}),
        json!({"input":[{"type":"reasoning", "summary":[], "encrypted_content":"opaque"}]}),
        json!({"input":[], "tools":[{"type":"namespace", "name":"a", "tools":[{"type":"namespace", "name":"b", "tools":[]}]}]}),
    ] {
        assert!(Adapter::request(request).is_err());
    }
    assert!(
        Adapter::default()
            .event(&mut json!({"item":{"type":"function_call", "name":"unadvertised"}}))
            .is_err()
    );
}
