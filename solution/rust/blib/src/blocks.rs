use std::process::Command;

use anyhow::{anyhow, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub hash: String,
    pub height: u32,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: String,
    #[serde(rename = "tx")]
    pub transactions: Vec<BlockTransaction>,
}

impl Block {
    pub fn from_height(height: u32) -> Result<Self> {
        let block_hash = get_block_hash(height)?;
        Block::from_hash(&block_hash)
    }

    pub fn from_hash(hash: &str) -> Result<Self> {
        get_block(hash)
    }

    pub fn next_block(&self) -> Result<Self> {
        Block::from_hash(&self.next_block_hash)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockTransaction {
    #[serde(rename = "txid")]
    pub id: String,
    #[serde(rename = "vin")]
    pub inputs: Vec<Input>,
    #[serde(rename = "vout")]
    pub outputs: Vec<Output>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Input {
    #[serde(rename = "txid")]
    pub transction_id: Option<String>,
    #[serde(rename = "vout")]
    pub output_index: Option<u32>,
    #[serde(rename = "txinwitness")]
    pub witness: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Output {
    pub value: f64,
    #[serde(rename = "n")]
    pub index: u32,
    #[serde(rename = "scriptPubKey")]
    pub pub_key: ScriptPubKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPubKey {
    pub asm: String,
    pub address: Option<String>,
}

fn bitcoin_cli(cmd: &str) -> Result<String> {
    let mut args = cmd.split(' ').collect::<Vec<&str>>();
    args.insert(0, "-signet");

    let result = Command::new("bitcoin-cli").args(&args).output()?;

    if result.status.success() {
        Ok(String::from_utf8(result.stdout)?.trim().to_string())
    } else {
        Err(anyhow!(
            "error sending bitcoin-cli command: {:?}",
            String::from_utf8(result.stderr)?.trim().to_string()
        ))
    }
}

fn get_block_hash(height: u32) -> Result<String> {
    let output = bitcoin_cli(&format!("getblockhash {}", height))?;
    Ok(output)
}

fn get_block(hash: &str) -> Result<Block> {
    let output = bitcoin_cli(&format!("getblock {} 3", hash))?;
    Ok(serde_json::from_str(&output)?)
}
