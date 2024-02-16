use std::collections::HashMap;

use blib::{Block, PrivateKey};

const DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPf3FPUm1wy3dZ8D1HbjSHJQvXyz3khqrNzCZrsGxenFKTZmzZdmAqUruzghUeFnepcoSnJrRoRn3hNbJ11atLw2Lzewd7TuG/84h/1h/0h/0/*)#y8k6un33";

fn main() {
    env_logger::init();

    // super bad. i know. quick and dirty.
    let parts = DESCRIPTOR
        .split("(")
        .last()
        .unwrap()
        .split(")")
        .next()
        .unwrap()
        .split("/")
        .collect::<Vec<_>>();

    let master_pvt_key = PrivateKey::from_xprv(parts[0]).unwrap();
    let paths = Vec::from(&parts[1..parts.len() - 1]);
    let child_pvt_key = master_pvt_key.get_child_at_path(paths).unwrap();
    let keys = (0..2000)
        .into_iter()
        .map(|n| child_pvt_key.get_child(n).unwrap())
        .map(|sk| sk.public_key().witness_program())
        .map(hex::encode)
        .collect::<Vec<_>>();

    let mut block = Block::from_height(1).unwrap();
    let mut utxos = HashMap::new();
    for _ in 0..310 {
        for tx in block.transactions.iter() {
            for input in tx.inputs.iter() {
                let Some(txid) = &input.transction_id else {
                    // skip coinbases since they won't have inputs from previous transactions
                    continue;
                };
                let outpoint = format!("{}:{}", txid, input.output_index.unwrap());

                utxos.remove(&outpoint);
            }
            for out in tx.outputs.iter() {
                if keys.iter().any(|k| out.pub_key.asm.ends_with(k)) {
                    let outpoint = format!("{}:{}", tx.id, out.index);
                    utxos.insert(outpoint, out.value);
                }
            }
        }

        block = block.next_block().unwrap();
    }

    let balance = utxos.values().sum::<f64>();

    println!("wallet_084 {:.8}", balance);
}
