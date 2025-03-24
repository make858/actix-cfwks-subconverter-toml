use serde::Deserialize;
use std::usize;
use rand::seq::SliceRandom;
use rand::thread_rng;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
struct Config {
    proxies: Proxy,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
struct Proxy {
    vless: Option<Vec<Node>>,
    trojan: Option<Vec<Node>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
struct Node {
    remarks_prefix: String,
    uuid: Option<String>, // vless拥有
    password: Option<String>, // trojan拥有
    host: String,
    server_name: String,
    path: String,
    random_ports: Vec<u16>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
struct SelectedNode {
    node_type: String,
    node: Node,
}

// 筛选数据
#[allow(dead_code)]
enum FilterCondition {
    Text(String),
    Number(u8),
}

#[allow(dead_code)]
fn selecting_config_of_node(
    proxys: &Proxy,
    poxy_type: String,
    nodeid: u8
) -> Result<SelectedNode, String> {
    let mut rng = thread_rng();

    let poxytype_value = FilterCondition::Text(poxy_type);
    let nodeid_value = FilterCondition::Number(nodeid);

    let vless_count: u8 = match proxys.vless.clone() {
        Some(vless) => vless.clone().len().try_into().unwrap(),
        None => 0,
    };
    let trojan_count: u8 = match proxys.trojan.clone() {
        Some(trojan) => trojan.clone().len().try_into().unwrap(),
        None => 0,
    };

    match (poxytype_value, nodeid_value) {
        // vless+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n)) if
            s == "vless" &&
            (1..=vless_count).contains(&n)
        =>
            match proxys.vless.clone() {
                Some(vless) =>
                    Ok(SelectedNode {
                        node_type: "vless".to_string(),
                        node: vless[(n as usize) - 1].clone(),
                    }),
                None => Err("请检查是否提供了vless节点的配置".to_string()),
            }

        // vless+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "vless" =>
            match proxys.vless.clone() {
                Some(vless) =>
                    Ok(SelectedNode {
                        node_type: "vless".to_string(),
                        node: vless.choose(&mut rng).unwrap().clone(),
                    }),
                None => Err("请检查是否提供了vless节点的配置".to_string()),
            }

        // trojan+指定id
        (FilterCondition::Text(ref s), FilterCondition::Number(n)) if
            s == "trojan" &&
            (1..=trojan_count).contains(&n)
        =>
            match proxys.trojan.clone() {
                Some(trojan) =>
                    Ok(SelectedNode {
                        node_type: "trojan".to_string(),
                        node: trojan[(n as usize) - 1].clone(),
                    }),
                None => Err("请检查是否提供了trojan节点的配置".to_string()),
            }

        // trojan+随机id
        (FilterCondition::Text(ref s), FilterCondition::Number(_)) if s == "trojan" =>
            match proxys.trojan.clone() {
                Some(trojan) =>
                    Ok(SelectedNode {
                        node_type: "trojan".to_string(),
                        node: trojan.choose(&mut rng).unwrap().clone(),
                    }),
                None => Err("请检查是否提供了trojan节点的配置".to_string()),
            }

        // 指定id，不论vless还是trojan
        (_, FilterCondition::Number(n)) if (1..=vless_count + trojan_count).contains(&n) => {
            let all_nodes = extend_all_nodes(proxys);
            match all_nodes.is_empty() {
                true => Err("请检查是否提供了vless或trojan节点的配置!".to_string()),
                false => Ok(all_nodes[(n as usize) - 1].clone()),
            }
        }

        // 随机节点，不论vless还是trojan
        (_, _) => {
            let all_nodes = extend_all_nodes(proxys);
            all_nodes
                .choose(&mut rng)
                .cloned()
                .ok_or("请检查是否提供了vless或trojan节点的配置!".to_string())
        }
    }
}

fn extend_all_nodes(proxys: &Proxy) -> Vec<SelectedNode> {
    let mut all_nodes: Vec<SelectedNode> = match proxys.trojan.clone() {
        Some(trojan) =>
            trojan
                .iter()
                .map(|p| SelectedNode {
                    node_type: "trojan".to_string(),
                    node: p.clone(),
                })
                .collect(),
        None => Vec::new(),
    };
    let vless_vec: Vec<SelectedNode> = match proxys.vless.clone() {
        Some(vless) =>
            vless
                .iter()
                .map(|p| SelectedNode { node_type: "vless".to_string(), node: p.clone() })
                .collect(),
        None => Vec::new(),
    };
    all_nodes.extend(vless_vec);
    all_nodes
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let toml_content = std::fs::read_to_string("config.toml")?;
    let toml_value: Config = toml::from_str(&toml_content)?;

    // 筛选节点的配置
    let in_proxy_type = "".to_string();
    let nodeid = 0;

    match selecting_config_of_node(&toml_value.proxies, in_proxy_type, nodeid) {
        Ok(prxy) => {
            println!("{}-remarks_prefix: {:?}", prxy.node_type, prxy.node.remarks_prefix);
            if prxy.node_type == "vless" {
                println!("{}-uuid: {}", prxy.node_type, prxy.node.uuid.unwrap_or_default());
            } else if prxy.node_type == "trojan" {
                println!("{}-password: {}", prxy.node_type, prxy.node.password.unwrap_or_default());
            }
            println!("{}-host: {:?}", prxy.node_type, prxy.node.host);
            println!("{}-server_name: {:?}", prxy.node_type, prxy.node.server_name);
            println!("{}-path: {:?}", prxy.node_type, prxy.node.path);
            println!("{}-random_ports: {:?}", prxy.node_type, prxy.node.random_ports);
        }
        Err(err) => {
            eprintln!("警告：{}", err);
        }
    }

    Ok(())
}
