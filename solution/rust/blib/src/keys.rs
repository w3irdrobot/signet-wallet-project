use anyhow::Result;
use bitcoin_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};
use k256::ecdsa::{DerSignature, Signature, SigningKey};
use k256::schnorr::signature::Signer;
use k256::{
    elliptic_curve::{ops::MulByGenerator, scalar::FromUintUnchecked, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar, U256,
};

#[derive(Debug, Clone)]
pub struct PrivateKey {
    chain_code: [u8; 32],
    scalar: Scalar,
}

impl PrivateKey {
    pub fn from_xprv(xprv: &str) -> Result<Self> {
        let plain = bs58::decode(xprv).into_vec()?;
        let chain_code: [u8; 32] = plain[13..45].try_into()?;
        // skipping byte 46 since this is a private key and will always be 0x0
        let priv_data: [u8; 32] = plain[46..78].try_into()?;
        let priv_num = U256::from_be_slice(&priv_data);
        let scalar = Scalar::from_uint_unchecked(priv_num);

        Ok(Self { chain_code, scalar })
    }

    pub fn public_key(&self) -> PublicKey {
        let point = ProjectivePoint::mul_by_generator(&self.scalar);

        PublicKey { point }
    }

    pub fn get_child_at_path(&self, paths: Vec<&str>) -> Result<Self> {
        let mut current = self.clone();
        for path in paths {
            if path.ends_with("h") {
                let child = path.strip_suffix("h").unwrap().parse::<u32>().unwrap();
                current = current.get_hardened_child(child).unwrap();
            } else {
                let child = path.parse::<u32>().unwrap();
                current = current.get_child(child).unwrap();
            }
        }

        Ok(current)
    }

    pub fn get_hardened_child(&self, child_n: u32) -> Result<Self> {
        let child = child_n + 0x80000000;

        let mut data: Vec<u8> = vec![0x00];
        data.extend(self.scalar.to_bytes().as_slice());
        data.extend(&child.to_be_bytes());

        self.child_from_data(data)
    }

    pub fn get_child(&self, child: u32) -> Result<Self> {
        let mut data: Vec<u8> = vec![];
        data.extend(&self.public_key().as_compressed_bytes()[..]);
        data.extend(&child.to_be_bytes());

        self.child_from_data(data)
    }

    fn child_from_data(&self, data: Vec<u8>) -> Result<Self> {
        let mut hmac_engine = HmacEngine::<sha512::Hash>::new(&self.chain_code);
        hmac_engine.input(&data);
        let hmac = Hmac::<sha512::Hash>::from_engine(hmac_engine);
        let hash = hmac.as_byte_array();

        let priv_data: [u8; 32] = hash[0..32].try_into()?;
        let priv_num = U256::from_be_slice(&priv_data);
        let new_scalar = Scalar::from_uint_unchecked(priv_num);
        let scalar = self.scalar + new_scalar;

        let chain_code = hash[32..64].try_into()?;

        Ok(Self { scalar, chain_code })
    }

    pub fn as_secret_bytes(&self) -> Box<[u8]> {
        self.scalar.to_bytes().as_slice().into()
    }

    // the signing implementation hashes the data once more before signing. so
    // commitments that require double sha256 should only use sha256 once and
    // let this method hash it a second time
    pub fn sign(&self, data: [u8; 32]) -> Result<DerSignature> {
        let key = SigningKey::from_bytes(&self.scalar.to_bytes())?;
        let signature: Signature = key.sign(&data);
        Ok(signature.to_der())
    }
}

pub struct PublicKey {
    point: ProjectivePoint,
}

impl PublicKey {
    pub fn as_bytes(&self) -> Box<[u8]> {
        let encoded = self.point.to_encoded_point(false).clone();
        encoded.to_bytes()
    }

    pub fn as_compressed_bytes(&self) -> Box<[u8]> {
        let encoded = self.point.to_encoded_point(true).clone();
        encoded.to_bytes()
    }

    pub fn witness_program(&self) -> [u8; 20] {
        hash160::Hash::hash(&self.as_compressed_bytes()).to_byte_array()
    }
}

#[cfg(test)]
mod test {
    use hex::{decode, encode};

    use super::*;

    fn get_master_key() -> PrivateKey {
        // from test vector 1: https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        let secret_data =
            decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35").unwrap();
        let priv_data: [u8; 32] = secret_data[..].try_into().unwrap();
        let priv_num = U256::from_be_slice(&priv_data);
        let scalar = Scalar::from_uint_unchecked(priv_num);

        let chain_code_data =
            decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508").unwrap();

        PrivateKey {
            scalar,
            chain_code: chain_code_data[..].try_into().unwrap(),
        }
    }

    #[test]
    fn gets_correct_public_key() {
        let master = get_master_key();
        let expected_sk = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let expected_pk = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
        let got_sk = encode(master.as_secret_bytes());
        let got_pk = encode(master.public_key().as_compressed_bytes());

        assert_eq!(expected_sk, got_sk);
        assert_eq!(expected_pk, got_pk);
    }

    #[test]
    fn get_correct_child_shallow() {
        let master = get_master_key();
        let expected_sk = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
        let expected_pk = "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56";
        let expected_cc = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";

        let child = master.get_child_at_path(vec!["0h"]).unwrap();
        let got_sk = encode(child.as_secret_bytes());
        let got_pk = encode(child.public_key().as_compressed_bytes());
        let got_cc = encode(&child.chain_code);

        assert_eq!(expected_sk, got_sk);
        assert_eq!(expected_pk, got_pk);
        assert_eq!(expected_cc, got_cc);
    }

    #[test]
    fn get_correct_child_deep() {
        let master = get_master_key();
        let expected_sk = "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4";
        let expected_pk = "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29";
        let expected_cc = "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd";

        let child = master
            .get_child_at_path(vec!["0h", "1", "2h", "2"])
            .unwrap();
        let got_sk = encode(child.as_secret_bytes());
        let got_pk = encode(child.public_key().as_compressed_bytes());
        let got_cc = encode(&child.chain_code);

        assert_eq!(expected_sk, got_sk);
        assert_eq!(expected_pk, got_pk);
        assert_eq!(expected_cc, got_cc);
    }
}
