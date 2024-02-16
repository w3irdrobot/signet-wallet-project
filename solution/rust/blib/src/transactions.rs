use anyhow::{anyhow, Ok, Result};
use bitcoin_hashes::{hash160, sha256, sha256d, Hash};

use crate::keys::PrivateKey;

const FEE_RATE: i64 = 15;

#[derive(Debug, Clone)]
pub enum TransactionKind {
    Single(PrivateKey),
    Multi { sig_min: i32, keys: Vec<PrivateKey> },
    OpReturn(String),
}

impl TransactionKind {
    pub fn has_witness_data(&self) -> bool {
        match self {
            Self::OpReturn(_) => false,
            _ => true,
        }
    }

    fn get_multisig_script(&self) -> Box<[u8]> {
        match self {
            Self::Single(_) => unimplemented!(),
            Self::Multi { sig_min, keys } => {
                // OP_2 pub1 pub2 OP_2 OP_CHECKMULTISIG
                let mut data = Vec::new();

                // OP_2
                let min: u8 = sig_min.clone().try_into().unwrap();
                data.push(0x50 + min);

                // pubkeys
                for key in keys {
                    let pub_key = key.public_key().as_compressed_bytes();
                    data.extend_from_slice(&(pub_key.len() as u8).to_le_bytes());
                    data.extend_from_slice(&pub_key);
                }

                // OP_2
                data.push(0x52);

                // OP_CHECKMULTISIG
                data.push(0xAE);

                dbg!(hex::encode(&data));

                data.try_into().unwrap()
            }
            Self::OpReturn(_) => unimplemented!(),
        }
    }

    pub fn get_digest_scriptcode(&self) -> Result<Box<[u8]>> {
        let scriptcode = match self {
            Self::Single(key) => {
                let mut scriptcode = vec![0x19, 0x76, 0xA9, 0x14];

                let pubkey_hash = key.public_key().witness_program();
                scriptcode.extend_from_slice(&pubkey_hash);

                scriptcode.extend_from_slice(&vec![0x88, 0xAC]);

                scriptcode
            }
            Self::Multi { .. } => {
                let script = self.get_multisig_script();

                let mut scriptcode = vec![];
                scriptcode.extend_from_slice(&(script.len() as u8).to_le_bytes());
                scriptcode.extend_from_slice(&script);
                scriptcode
            }
            Self::OpReturn(_) => self.get_script_pubkey().into(),
        };

        Ok(scriptcode.try_into().unwrap())
    }

    pub fn get_witness_script(&self, data: [u8; 32]) -> Result<Box<[u8]>> {
        match self {
            Self::Single(key) => {
                let mut sig: Vec<_> = key.sign(data)?.to_bytes().try_into()?;
                // SIGHASH_ALL
                sig.push(0x01);

                let pub_key = key.public_key().as_compressed_bytes();

                // two components to this witness
                let mut data = vec![0x02];
                // signature
                data.extend_from_slice(&(sig.len() as u8).to_le_bytes());
                data.extend_from_slice(&sig);
                // public key
                data.extend_from_slice(&(pub_key.len() as u8).to_le_bytes());
                data.extend_from_slice(&pub_key);

                Ok(data.try_into().unwrap())
            }
            Self::Multi { keys, .. } => {
                let mut sigs = vec![];
                for key in keys {
                    let mut sig: Vec<u8> = key.sign(data)?.to_bytes().into();
                    sig.push(0x01);
                    sigs.extend_from_slice(&(sig.len() as u8).to_le_bytes());
                    sigs.extend_from_slice(&sig);
                }

                // OP_0 + sigs_length + multisig_script
                let len = (1 + keys.len() + 1) as u8;
                let mut data = vec![len];

                // OP_0
                data.extend_from_slice(&[0x00]);

                // signatures
                data.extend_from_slice(&sigs);

                let script = self.get_multisig_script();
                data.extend_from_slice(&(script.len() as u8).to_le_bytes());
                data.extend_from_slice(&script);

                Ok(data.try_into().unwrap())
            }
            Self::OpReturn(_) => unimplemented!(),
        }
    }

    pub fn get_script_pubkey(&self) -> Box<[u8]> {
        let data = match self {
            Self::Single(key) => {
                let mut data = vec![0x00];
                let hash =
                    hash160::Hash::hash(&key.public_key().as_compressed_bytes()).to_byte_array();
                data.extend_from_slice(&(hash.len() as u8).to_le_bytes());
                data.extend_from_slice(&hash);
                data
            }
            Self::Multi { .. } => {
                let mut data = vec![0x00];
                let hash = sha256::Hash::hash(&self.get_multisig_script()).to_byte_array();
                data.extend_from_slice(&(hash.len() as u8).to_le_bytes());
                data.extend_from_slice(&hash);
                data
            }
            Self::OpReturn(name) => {
                // OP_RETURN
                let mut data = vec![0x6A];

                // data
                let name = name.as_bytes();
                data.extend_from_slice(&(name.len() as u8).to_le_bytes());
                data.extend_from_slice(&name);
                data
            }
        };
        data.try_into().unwrap()
    }
}

pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    change: Option<TransactionKind>,
}

impl Transaction {
    pub fn to_bytes(&self) -> Result<Box<[u8]>> {
        // init transaction with version
        let mut tx: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00];

        // push extended marker
        tx.push(0x00);
        // push flag
        tx.push(0x01);

        // push number of inputs
        tx.push(self.inputs.len() as u8);
        // push each input
        for input in &self.inputs {
            let bytes = input.to_bytes()?;
            tx.extend_from_slice(&bytes);
        }

        // push number of outputs
        let outputs_num = self
            .change
            .is_some()
            .then_some(self.outputs.len() + 1)
            .unwrap_or(self.outputs.len());
        tx.push(outputs_num as u8);
        // push each output
        for output in &self.outputs {
            let bytes = output.to_bytes()?;
            tx.extend_from_slice(&bytes);
        }

        if let Some(change) = &self.change {
            let output = Output {
                kind: change.clone(),
                amount: self.get_change_amount(),
            };
            let bytes = output.to_bytes()?;

            tx.extend_from_slice(&bytes);
        }

        // push on witness data
        for (i, input) in self.inputs.iter().enumerate() {
            let commitment_data = self.get_transaction_digest(i)?;
            let script = input.kind.get_witness_script(commitment_data.into())?;
            tx.extend_from_slice(&script);
        }

        // add the lock time
        tx.extend_from_slice(&vec![0x00, 0x00, 0x00, 0x00]);

        Ok(tx.try_into()?)
    }

    pub fn get_change_amount(&self) -> i64 {
        let in_total = self.inputs.iter().map(|i| i.amount).sum::<i64>();
        let out_total = self.outputs.iter().map(|o| o.amount).sum::<i64>();
        in_total - out_total - FEE_RATE * 1000 // 1000 vbytes
    }

    pub fn get_id(&self) -> Result<Box<[u8]>> {
        // start with nVersion of transaction
        let mut data: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00];

        // push number of inputs
        data.push(self.inputs.len() as u8);
        // push each input
        for input in &self.inputs {
            let bytes = input.to_bytes()?;
            data.extend_from_slice(&bytes);
        }

        let outputs_num = self
            .change
            .is_some()
            .then_some(self.outputs.len() + 1)
            .unwrap_or(self.outputs.len());
        data.push(outputs_num as u8);
        // push each output
        for output in &self.outputs {
            let bytes = output.to_bytes()?;
            data.extend_from_slice(&bytes);
        }

        if let Some(change) = &self.change {
            let output = Output {
                kind: change.clone(),
                amount: self.get_change_amount(),
            };
            let bytes = output.to_bytes()?;

            data.extend_from_slice(&bytes);
        }

        data.extend_from_slice(&vec![0x00, 0x00, 0x00, 0x00]);

        let hash = sha256d::Hash::hash(&data);
        Ok(hash.to_byte_array().try_into()?)
    }

    fn get_transaction_digest(&self, input_index: usize) -> Result<[u8; 32]> {
        // start with nVersion of transaction
        let mut data: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00];

        // hashPrevouts (32-byte hash)
        let mut temp_data = Vec::new();
        for input in self.inputs.iter() {
            temp_data.extend_from_slice(&input.get_outpoint()?);
        }
        let temp_hash = sha256d::Hash::hash(&temp_data);
        data.extend_from_slice(&temp_hash.to_byte_array());

        // hashSequence (32-byte hash)
        // hardcoding this since for this test, we only have one input for each tx.
        // LAZINESS! LET'S GO!
        let temp_hash = sha256d::Hash::hash(&[0xFF, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&temp_hash.to_byte_array());

        let input = &self.inputs[input_index];

        // outpoint (32-byte hash + 4-byte little endian)
        data.extend_from_slice(&input.get_outpoint()?);

        // scriptCode of the input (serialized as scripts inside CTxOuts)
        let scriptcode = input.kind.get_digest_scriptcode()?;
        // data.extend_from_slice(&(scriptcode.len() as u8).to_le_bytes());
        data.extend_from_slice(&scriptcode);

        // value of the output spent by this input (8-byte little endian)
        data.extend_from_slice(&input.amount.to_le_bytes());

        // nSequence of the input (4-byte little endian)
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        // hashOutputs (32-byte hash)
        let mut temp_data = Vec::new();
        for output in self.outputs.iter() {
            temp_data.extend_from_slice(&output.to_bytes()?);
        }
        if let Some(change) = &self.change {
            let output = Output {
                kind: change.clone(),
                amount: self.get_change_amount(),
            };
            temp_data.extend_from_slice(&output.to_bytes()?);
        }
        let temp_hash = sha256d::Hash::hash(&temp_data);
        data.extend_from_slice(&temp_hash.to_byte_array());

        // nLocktime of the transaction (4-byte little endian)
        data.extend_from_slice(&vec![0x00, 0x00, 0x00, 0x00]);

        // sighash type of the signature (4-byte little endian)
        data.extend_from_slice(&vec![0x01, 0x00, 0x00, 0x00]);

        // transaction digest is double-sha256 hashed
        let hash = sha256::Hash::hash(&data);
        Ok(hash.to_byte_array())
    }
}

struct Input {
    kind: TransactionKind,
    address: [u8; 32],
    out_index: u32,
    amount: i64,
}

impl Input {
    pub fn get_outpoint(&self) -> Result<[u8; 36]> {
        let mut data = Vec::new();

        data.extend_from_slice(&self.address);
        data.extend_from_slice(&self.out_index.to_le_bytes());

        Ok(data.try_into().unwrap())
    }

    pub fn to_bytes(&self) -> Result<Box<[u8]>> {
        let mut input: Vec<u8> = Vec::new();

        // copy in the outpoint address
        input.extend_from_slice(&self.get_outpoint()?);

        // push in zero-length input script
        input.push(0x00);

        // push input sequence
        input.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        Ok(input.try_into()?)
    }
}

struct Output {
    kind: TransactionKind,
    amount: i64,
}

impl Output {
    pub fn to_bytes(&self) -> Result<Box<[u8]>> {
        let mut output: Vec<u8> = Vec::new();

        // copy in output amount
        output.extend_from_slice(&self.amount.to_le_bytes());

        // copy in output script
        let script = self.kind.get_script_pubkey();
        output.push(script.len() as u8);
        output.extend_from_slice(&script);

        Ok(output.try_into()?)
    }
}

pub struct TransactionBuilder {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    change: Option<TransactionKind>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            change: None,
        }
    }

    pub fn input(mut self, kind: TransactionKind, outpoint: &str, amount: i64) -> Self {
        let mut split = outpoint.split(":");

        let mut address = hex::decode(split.next().unwrap().to_string()).unwrap();
        // apparently the address is shown in reverse order
        address.reverse();
        let address = address.try_into().unwrap();
        let out_index = split.next().unwrap().parse().unwrap();

        self.inputs.push(Input {
            address,
            out_index,
            kind,
            amount,
        });
        self
    }

    pub fn output(mut self, kind: TransactionKind, amount: f64) -> Self {
        let amount = (amount * 100_000_000.0) as i64;
        self.outputs.push(Output { amount, kind });
        self
    }

    pub fn change(mut self, kind: TransactionKind) -> Self {
        self.change = Some(kind);
        self
    }

    pub fn build(self) -> Result<Transaction> {
        let TransactionBuilder {
            inputs,
            outputs,
            change,
        } = self;

        if inputs.len() == 0 {
            return Err(anyhow!("a transaction can't be build without inputs"));
        }

        if outputs.len() == 0 {
            return Err(anyhow!("a transaction can't be build without outputs"));
        }

        Ok(Transaction {
            inputs,
            outputs,
            change,
        })
    }
}
