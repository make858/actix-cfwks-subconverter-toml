use yaml_rust::{ YamlEmitter, YamlLoader };

#[allow(dead_code)]
/// 调整YAML缩进
pub fn adjust_yaml_indentation(yaml_str: &str) -> String {
    let data = YamlLoader::load_from_str(yaml_str).ok();
    let doc = data.as_ref().and_then(|d| d.first());

    let mut output = String::new();
    if let Some(doc) = doc {
        let mut emitter = YamlEmitter::new(&mut output);
        if emitter.dump(doc).is_err() {
            return "Error: Failed to emit YAML".to_string();
        }
    } else {
        return "Error: No document found in YAML input".to_string();
    }

    output.strip_prefix("---\n").unwrap_or(&output).to_string()
}
