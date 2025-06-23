use clap::{builder::Str, Parser};
use reqwest;
use serde_json::{Result, Value};
use serde::{Deserialize, Serialize};


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// token for agent (hashed id)
    #[arg(short, long)]
    token: String,

    /// agent url
    #[arg(short, long)]
    url: String,
}
#[derive(Deserialize, Debug)]
struct RegisterResponse {
    message: String,
}


fn main() {
    let args = Args::parse();
    let token = args.token;
    let url = args.url;
}

#[tokio::main]
async fn register(token: String, url: String) -> String {
    

    return  "aa".to_string();
}

