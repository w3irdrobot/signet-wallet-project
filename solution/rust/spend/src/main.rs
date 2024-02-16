use blib::{PrivateKey, TransactionBuilder, TransactionKind};

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

    let mut pvt_key = PrivateKey::from_xprv(parts[0]).unwrap();
    let paths = Vec::from(&parts[1..parts.len() - 1]);
    pvt_key = pvt_key.get_child_at_path(paths).unwrap();

    // "621b5be5473dee990936ea24adf01b584bec6d018c5b4fc41d83365b62f4d9c8:1": Output {
    //     amount: 7.84550353,
    //     pk_index: 423,
    // }
    let child_key_423 = pvt_key.get_child(423).unwrap();

    let child_key_0 = pvt_key.get_child(0).unwrap();
    let child_key_1 = pvt_key.get_child(1).unwrap();

    let tx1 = TransactionBuilder::new()
        .input(
            TransactionKind::Single(child_key_423),
            "621b5be5473dee990936ea24adf01b584bec6d018c5b4fc41d83365b62f4d9c8:1",
            784550353,
        )
        .output(
            TransactionKind::Multi {
                sig_min: 2,
                keys: vec![child_key_0.clone(), child_key_1.clone()],
            },
            0.01,
        )
        .change(TransactionKind::Single(child_key_0.clone()))
        .build()
        .unwrap();
    let tx1_serialized = tx1.to_bytes().unwrap();

    let mut tx1_id = tx1.get_id().unwrap();
    tx1_id.reverse();

    let tx1_address = hex::encode(tx1_id);
    println!("{}", hex::encode(tx1_serialized));

    let tx2 = TransactionBuilder::new()
        .input(
            TransactionKind::Multi {
                sig_min: 2,
                keys: vec![child_key_0.clone(), child_key_1],
            },
            &format!("{}:0", tx1_address),
            1_000_000,
        )
        .output(TransactionKind::OpReturn("w3irdrobot".to_string()), 0.0)
        .change(TransactionKind::Single(child_key_0.clone()))
        .build()
        .unwrap();
    let tx2_serialized = tx2.to_bytes().unwrap();

    println!("{}", hex::encode(tx2_serialized));
}
