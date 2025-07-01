use clap::{builder::Str, Parser};
use reqwest;
use serde_json::{Result, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use reqwest::Error;


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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let agent_id = args.agent_id;
    let url = args.url;

    let jwt_token = register(&agent_id, &url).await;

    loop {
        let command = getCommand(&jwt_token, &url, &agent_id).await;
        println!("Received command: {}", command);
        // Do something with the command...
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

async fn getCommand(token: &String, url: &String, agent_id: &String) -> String {
    let cmd = "".to_string();
    let mut new_url = url.clone();
    new_url.push_str(agent_id);
    new_url.push_str("/plan");
    

    return cmd;
}


