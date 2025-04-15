use crate::utils::toml::{selecting_config_of_node, Proxy};
use rand::seq::SliceRandom;
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;

pub fn build_clash_json(
    toml_proxies: &Proxy,
    csv_tag: String,
    csv_addr: String,
    csv_port: u16,
    uri_port: u16,
    uri_userid: u8,
    uri_proxy_type: String,
    fingerprint: String,
    http_ports: &[u16; 7],  // 非TLS 模式下，http的端口
    https_ports: &[u16; 6], // TLS 模式下，https的端口
) -> (String, JsonValue) {
    for _ in 0..100 {
        match selecting_config_of_node(toml_proxies, uri_proxy_type.clone(), uri_userid) {
            Ok(prxy) => {
                let node_type = prxy.node_type.as_str();
                let toml_tag: String = prxy.node.remarks_prefix;
                let host: String = prxy.node.host;
                let server_name: String = prxy.node.server_name.unwrap_or_default();
                let toml_ss_tls = prxy.node.tls.unwrap_or(true);
                let path: String = prxy.node.path;

                let condition = if ["vless", "trojan"].contains(&node_type) {
                    host.ends_with("workers.dev")
                } else {
                    !toml_ss_tls // ss协议的
                };

                let (mut ports, reverse_ports) = match condition {
                    true => (http_ports.to_vec(), https_ports.to_vec()),
                    false => (https_ports.to_vec(), http_ports.to_vec()),
                };
                // 注意：不会检查配置文件的端口是否合法
                ports = prxy.node.random_ports.unwrap_or(ports);

                let (port, is_continue) = match (uri_port == 0, csv_port == 0) {
                    (true, true) => (*ports.choose(&mut rand::thread_rng()).unwrap(), false), // uri端口与csv端口都没有，就随机选一个端口
                    (true, false) => (csv_port, reverse_ports.contains(&csv_port)), // csv端口有，就使用csv端口
                    (false, true) => (uri_port, reverse_ports.contains(&uri_port)), // uri端口有，就使用uri端口
                    (false, false) => (uri_port, false), // uri端口与csv端口都有，不管端口是否能使用，都使用uri端口
                };
                // 端口不匹配，开启tls和没有开启tls的端口不同，需要换另一个配置
                if is_continue {
                    continue;
                }
                // 节点的别名
                let remarks = match (csv_tag.trim().is_empty(), toml_tag.is_empty()) {
                    (true, true) => format!("{}:{}", csv_addr, port), // cvs_tag与toml_tag都没有
                    (false, true) => format!("{}|{}:{}", csv_tag, csv_addr, port), // 仅有csv_tag
                    (true, false) => format!("{}|{}:{}", toml_tag, csv_addr, port), // 仅有toml_tag
                    (false, false) => format!("{}{}|{}:{}", toml_tag, csv_tag, csv_addr, port), // 既有csv_tag，也有toml_tag
                };

                match node_type {
                    "vless" => {
                        let (remarks, jsonvalue) = build_vless_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.uuid.unwrap_or_default(),
                            host,
                            server_name,
                            path,
                            fingerprint,
                        );
                        return (remarks, jsonvalue);
                    }
                    "trojan" => {
                        let (remarks, jsonvalue) = build_trojan_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.password.unwrap_or_default(),
                            host,
                            server_name,
                            path,
                            fingerprint,
                        );
                        return (remarks, jsonvalue);
                    }
                    "ss" => {
                        let (remarks, jsonvalue) = build_ss_clash(
                            remarks,
                            csv_addr.clone(),
                            port,
                            prxy.node.password.unwrap_or("none".to_string()),
                            toml_ss_tls,
                            host,
                            path,
                        );
                        return (remarks, jsonvalue);
                    }
                    _ => {
                        return ("".to_string(), JsonValue::Null);
                    }
                }
            }
            Err(err) => eprintln!("警告：{}", err),
        }
    }
    return ("".to_string(), JsonValue::Null);
}

fn build_ss_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_tls: bool,
    toml_host: String,
    toml_path: String,
) -> (String, serde_json::Value) {
    let ss_with_clash = r#"{
        "name": "ss-v2ray",
        "type": "ss",
        "server": "",
        "port": 443,
        "cipher": "none",
        "password": "",
        "udp": false,
        "plugin": "v2ray-plugin",
        "plugin-opts": {
            "mode": "websocket",
            "path": "/",
            "host": "",
            "tls": true,
            "mux": false
        }
    }"#;

    let mut ss_json: JsonValue = serde_json::from_str(ss_with_clash).unwrap_or_default();
    ss_json["name"] = json!(remarks);
    ss_json["server"] = json!(csv_addr);
    ss_json["port"] = json!(port);
    ss_json["password"] = json!(toml_password);
    ss_json["plugin-opts"]["host"] = json!(toml_host);
    ss_json["plugin-opts"]["tls"] = json!(toml_tls);
    ss_json["plugin-opts"]["path"] = json!(toml_path);

    (remarks, ss_json)
}

fn build_trojan_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_password: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, serde_json::Value) {
    let trojan_with_clash = r#"{
        "type": "trojan",
        "name": "",
        "server": "",
        "port": 443,
        "password": "",
        "network": "ws",
        "udp": false,
        "sni": "",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
            "path": "/",
            "headers": {"Host": ""}
        }
    }"#;

    let mut trojan_json: JsonValue = serde_json::from_str(trojan_with_clash).unwrap_or_default();

    let password_vec = vec!["password".to_string(), toml_password];
    let sni_vec = vec!["sni".to_string(), toml_server_name];

    modify_clash_json_value(
        &mut trojan_json,
        remarks.clone(),
        csv_addr,
        port,
        password_vec,
        toml_host,
        sni_vec,
        toml_path,
        fingerprint,
    );

    (remarks, trojan_json)
}

fn build_vless_clash(
    remarks: String,
    csv_addr: String,
    port: u16,
    toml_uuid: String,
    toml_host: String,
    toml_server_name: String, // sni
    toml_path: String,
    fingerprint: String,
) -> (String, serde_json::Value) {
    let vless_with_clash = r#"{
        "type": "vless",
        "name": "tag_name",
        "server": "",
        "port": 443,
        "uuid": "",
        "network": "ws",
        "tls": true,
        "udp": false,
        "servername": "",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
            "path": "/",
            "headers": {"Host": ""}
        }
    }"#;
    let mut vless_json: JsonValue = serde_json::from_str(vless_with_clash).unwrap_or_default();

    // 遇到host是workers.dev的，手动修改tls为false
    if toml_host.ends_with("workers.dev") {
        vless_json.as_object_mut().map(|obj| {
            obj.insert("tls".to_string(), JsonValue::Bool(false));
        });
    }

    let uuid_vec = vec!["uuid".to_string(), toml_uuid];
    let servername_vec = vec!["servername".to_string(), toml_server_name];

    modify_clash_json_value(
        &mut vless_json,
        remarks.clone(),
        csv_addr,
        port,
        uuid_vec,
        toml_host,
        servername_vec,
        toml_path,
        fingerprint,
    );

    (remarks, vless_json)
}

fn modify_clash_json_value(
    jsonvalue: &mut JsonValue,
    remarks: String,
    csv_addr: String,
    port: u16,
    uuid_or_password: Vec<String>, // 修改vless的uuid，trojan的password
    host: String,
    sni: Vec<String>, // 修改vless的servername字段，trojan的sni
    path: String,
    fingerprint: String,
) {
    // 修改顶层字段值
    if let Some(obj) = jsonvalue.as_object_mut() {
        // vless的uuid，trojan的password
        obj.insert(
            uuid_or_password[0].to_string(),
            JsonValue::String(uuid_or_password[1].to_string()),
        );
        // vless的servername，trojan的sni
        obj.insert(sni[0].to_string(), JsonValue::String(sni[1].to_string()));
        obj.insert(
            "client-fingerprint".to_string(),
            JsonValue::String(fingerprint),
        );
        obj.insert("name".to_string(), JsonValue::String(remarks));
        obj.insert("server".to_string(), JsonValue::String(csv_addr));
        obj.insert("port".to_string(), JsonValue::Number(port.into()));
    }

    // 修改ws-opts字段里面其它字段值
    if let Some(ws_opts) = jsonvalue.get_mut("ws-opts") {
        if let Some(ws_opts_obj) = ws_opts.as_object_mut() {
            ws_opts_obj.insert("path".to_string(), JsonValue::String(path));
            if let Some(headers) = ws_opts_obj.get_mut("headers") {
                if let Some(headers_obj) = headers.as_object_mut() {
                    headers_obj.insert("Host".to_string(), JsonValue::String(host));
                }
            }
        }
    }
}

pub fn add_clash_template(clash_template: &mut YamlValue, clash_data: Vec<(String, String)>) {
    // 处理节点信息
    if let Some(outside_proxies) = clash_template.get_mut("proxies") {
        if let serde_yaml::Value::Sequence(array) = outside_proxies {
            array.clear(); // 清空数组

            let proxies_vec: Vec<serde_yaml::Value> = clash_data
                .iter()
                .filter_map(|(_k, v)| {
                    // 将 JSON 字符串解析为 serde_json::Value
                    let json_value: JsonValue = serde_json::from_str(v).unwrap();
                    // 将 serde_json::Value 转换为 serde_yaml::Value
                    let yaml_value: YamlValue =
                        serde_yaml::from_str(&serde_json::to_string(&json_value).unwrap()).unwrap();
                    Some(yaml_value)
                })
                .collect::<Vec<_>>()
                .to_vec();
            array.extend(proxies_vec);
        }
    }
    // 处理代理组名称
    if let Some(proxy_groups) = clash_template.get_mut("proxy-groups") {
        if let YamlValue::Sequence(array) = proxy_groups {
            array.iter_mut().for_each(|groups| {
                groups.get_mut("proxies").and_then(|proxies_seq| {
                    if let YamlValue::Sequence(ref mut seq) = proxies_seq {
                        let mut contains_s01 = false;
                        let mut filtered_s01_with_proxies: Vec<YamlValue> = Vec::new();
                        // 遍历并处理 proxies 数组（里面的proxies字段值）
                        seq.drain(..).for_each(|item| {
                            if let YamlValue::String(ref s) = item {
                                match s == "s01" {
                                    true => {
                                        contains_s01 = true;
                                    }
                                    false => filtered_s01_with_proxies.push(item),
                                }
                            }
                        });
                        match contains_s01 {
                            true => {
                                filtered_s01_with_proxies.extend(
                                    clash_data
                                        .iter()
                                        .map(|(k, _v)| k.to_string())
                                        .collect::<Vec<_>>()
                                        .to_vec()
                                        .into_iter()
                                        .map(|name| YamlValue::String(name.to_string())),
                                );
                            }
                            false => {}
                        }
                        *seq = filtered_s01_with_proxies;
                    }
                    return proxies_seq.as_sequence_mut();
                });
            });
        }
    }
}
