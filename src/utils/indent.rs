use yaml_rust::{ YamlEmitter, YamlLoader };

/// 调整 YAML 缩进
pub fn adjust_yaml_indentation(yaml_str: &str) -> String {
    // 尝试加载和处理 YAML 数据
    let data = match YamlLoader::load_from_str(yaml_str) {
        Ok(data) => data,
        Err(_) => {
            return "Error: Failed to parse YAML input".to_string();
        }
    };
    // 获取第一个文档
    let doc = if let Some(doc) = data.get(0) {
        doc
    } else {
        return "Error: No document found in YAML input".to_string();
    };
    let mut output = String::new();
    let mut emitter = YamlEmitter::new(&mut output);
    // 尝试将文档转储到输出字符串
    if emitter.dump(doc).is_ok() {
        // 去掉开头的 `---\n`（如果存在的话）
        if output.starts_with("---\n") {
            return output[4..].to_string();
        }
        return output;
    } else {
        return "Error: Failed to emit YAML".to_string();
    }
}
