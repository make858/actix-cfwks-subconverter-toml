use serde::Deserialize;
use std::fs;
use rand::seq::SliceRandom;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    proxies: ProxyType,
}

#[derive(Debug, Deserialize, Clone)]
struct ProxyType {
    vless: Vec<Node>,
    trojan: Vec<Node>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Node {
    #[serde(default)] // 设置为默认值
    remarks_prefix: String,
    #[serde(default)] // 防止读取toml文件时，找不到该参数报错
    uuid: String,
    #[serde(default)] // 防止读取toml文件时，找不到该参数报错
    password: String,

    host: String,
    server_name: String,
    random_ports: Vec<u16>,

    #[serde(default = "path_empty")] // 设置"/"路径为默认值
    path: String,
}

fn path_empty() -> String {
    "/".to_string()
}

pub fn select_toml_proxy(config: &Config, pos: usize, proxy_type: String) -> Result<Node, String> {
    // 注意：vless的代理节点在前面，trojan的代理节点在后面
    let mut all_proxy_nodes: Vec<Node> = config.proxies.vless.clone();
    all_proxy_nodes.extend(config.proxies.trojan.clone());

    // 优先选择指定位置的代理，当传入的值不合理时，才执行后面的代码
    if (1..all_proxy_nodes.len() + 1).contains(&pos) {
        if let Some(proxy_at_pos) = all_proxy_nodes.get(pos - 1) {
            return Ok(proxy_at_pos.clone());
        }
    }

    // 根据传入的参数选择代理类型(vless、trojan)，当不指定具体的代理类型时，走`_`分支，随机生成一个(不区分vless/trojan)
    match proxy_type.as_str() {
        "vless" => {
            if let Some(random_vless) = config.proxies.vless.choose(&mut rand::thread_rng()) {
                return Ok(random_vless.clone());
            } else {
                return Err(format!("似乎您的toml配置文件中，不存在 {} 类型的代理信息", proxy_type));
            }
        }
        "trojan" => {
            if let Some(random_trojan) = config.proxies.trojan.choose(&mut rand::thread_rng()) {
                return Ok(random_trojan.clone());
            } else {
                return Err(format!("似乎您的toml配置文件中，不存在 {} 类型的代理信息", proxy_type));
            }
        }
        _ => {
            // 兜底代码，传入的pos、proxy_type参数都不符合代码逻辑时，才执行这个代码
            if let Some(random_proxies) = all_proxy_nodes.clone().choose(&mut rand::thread_rng()) {
                return Ok(random_proxies.clone().clone());
            } else {
                Err("toml文件中的配置信息为空!".to_string())
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 读取并解析 TOML 配置文件
    let config_content = fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_content).unwrap();

    match select_toml_proxy(&config, 0, "vless".to_string()) {
        Ok(node) => {
            println!("{}", node.remarks_prefix);
            println!("{}{}", node.uuid, node.password);
            println!("{}", node.host);
            println!("{}", node.server_name);
            println!("{}", node.path);
            println!("{:?}", node.random_ports);
        }
        Err(err) => {
            println!("{}", err);
        }
    }
    Ok(())
}
