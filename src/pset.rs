use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use bitcoin::util::bip32;
use elements::SigHashType;
use elements::hashes::Hash;
use elements::{pset, encode};
use Network;

use hal::HexBytes;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsetGlobalInfo {
	pub version: u32,
	pub tx_version: u32,
	pub num_inputs: u32,
	pub num_outputs: u32,
	pub fallback_locktime: u32,
	pub tx_modifiable: u8,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub xpub: HashMap<String, String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub scalars: Vec<::HexBytes>,
	pub elements_tx_modifiable_flag: u8,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub proprietary: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub unknown: HashMap<::HexBytes, ::HexBytes>,
}

impl ::GetInfo<PsetGlobalInfo> for pset::Global {
	fn get_info(&self, _network: Network) -> PsetGlobalInfo {
		PsetGlobalInfo {
		    version: self.version,
		    tx_version: self.tx_data.version,
		    num_inputs: self.n_inputs() as u32,
		    num_outputs: self.n_outputs() as u32,
		    fallback_locktime: self.tx_data.fallback_locktime.unwrap_or(0),
		    tx_modifiable: self.tx_data.tx_modifiable.unwrap_or(0),
		    xpub: {
				let mut xpubs = HashMap::new();
				for (k, (f, d)) in &self.xpub {
					let x = format!("({},{})", f.to_string(), d.to_string());
					xpubs.insert(k.to_string(), x);
				}
				xpubs
			},
		    scalars: {
				let mut scalars = Vec::new();
				for x in &self.scalars {
					scalars.push(HexBytes::from(x.to_vec()));
				}
				scalars
			},
		    elements_tx_modifiable_flag: self.elements_tx_modifiable_flag.unwrap_or(0),
		    proprietary: {
				let mut proprietary = HashMap::new();
				for (k, v) in &self.proprietary {
					proprietary.insert(
						HexBytes::from(encode::serialize(&k.to_key())),
						HexBytes::from(v.to_vec()),
					);
				}
				proprietary
			},
		    unknown: {
				let mut unknown = HashMap::new();
				for (k, v) in &self.unknown {
					unknown.insert(
						HexBytes::from(encode::serialize(k)),
						HexBytes::from(v.to_vec()),
					);
				}
				unknown
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct HDPathInfo {
	pub master_fingerprint: bip32::Fingerprint,
	pub path: bip32::DerivationPath,
}

pub fn sighashtype_to_string(sht: SigHashType) -> String {
	use elements::SigHashType::*;
	match sht {
		All => "ALL",
		None => "NONE",
		Single => "SINGLE",
		AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
		NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
		SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
	}.to_owned()
}

pub fn sighashtype_values() -> &'static [&'static str] {
	&["ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"]
}

pub fn sighashtype_from_string(sht: &str) -> SigHashType {
	use elements::SigHashType::*;
	match sht {
		"ALL" => All,
		"NONE" => None,
		"SINGLE" => Single,
		"ALL|ANYONECANPAY" => AllPlusAnyoneCanPay,
		"NONE|ANYONECANPAY" => NonePlusAnyoneCanPay,
		"SINGLE|ANYONECANPAY" => SinglePlusAnyoneCanPay,
		_ => panic!("invalid SIGHASH type value -- possible values: {:?}", &sighashtype_values()),
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsetInputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub non_witness_utxo: Option<::tx::TransactionInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_utxo: Option<::tx::OutputInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub partial_sigs: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sighash_type: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<::HexBytes, HDPathInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_sig: Option<::tx::InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_witness: Option<Vec<::HexBytes>>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub ripemd160_preimages: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub sha256_preimages: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub hash160_preimages: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub hash256_preimages: HashMap<::HexBytes, ::HexBytes>,
    pub previous_txid: ::HexBytes,
    pub previous_output_index: u32,
    pub sequence: u32,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub required_time_locktime: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub required_height_locktime: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_value: Option<::confidential::ConfidentialValueInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_value_rangeproof: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_keys_rangeproof: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_tx: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_txout_proof: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_genesis_hash: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_claim_script: Option<::tx::InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_value: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub pegin_witness: Option<Vec<::HexBytes>>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_inflation_keys: Option<::confidential::ConfidentialValueInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_blinding_nonce: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_asset_entropy: Option<::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub proprietary: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub unknown: HashMap<::HexBytes, ::HexBytes>,
}

impl ::GetInfo<PsetInputInfo> for pset::Input {
	fn get_info(&self, network: Network) -> PsetInputInfo {
		PsetInputInfo {
			non_witness_utxo: self.non_witness_utxo.as_ref().map(|u| u.get_info(network)),
			witness_utxo: self.witness_utxo.as_ref().map(|u| u.get_info(network)),
			partial_sigs: {
				let mut partial_sigs = HashMap::new();
				for (key, value) in self.partial_sigs.iter() {
					partial_sigs.insert(key.to_bytes().into(), value.clone().into());
				}
				partial_sigs
			},
			sighash_type: self.sighash_type.map(sighashtype_to_string),
			redeem_script: self.redeem_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			hd_keypaths: {
				let mut hd_keypaths = HashMap::new();
				for (key, value) in self.bip32_derivation.iter() {
					hd_keypaths.insert(key.to_bytes().into(),
						HDPathInfo {
							master_fingerprint: value.0[..].into(),
							path: value.1.clone(),
						},
					);
				}
				hd_keypaths
			},
			final_script_sig: self.final_script_sig.as_ref()
				.map(|s| ::tx::InputScript(s).get_info(network)),
			final_script_witness: self.final_script_witness.as_ref()
				.map(|w| w.iter().map(|p| p.clone().into()).collect()),
		    ripemd160_preimages: {
				let mut ripemd160_map = HashMap::new();
				for (k, v) in &self.ripemd160_preimages{
					ripemd160_map.insert(
						HexBytes::from(k.as_inner().to_vec()),
						HexBytes::from(v.to_vec())
					);
				}
				ripemd160_map
			},
		    sha256_preimages: {
				let mut sha256_map = HashMap::new();
				for (k, v) in &self.sha256_preimages{
					sha256_map.insert(
						HexBytes::from(k.as_inner().to_vec()),
						HexBytes::from(v.to_vec())
					);
				}
				sha256_map
			},
		    hash160_preimages: {
				let mut hash160_map = HashMap::new();
				for (k, v) in &self.hash160_preimages{
					hash160_map.insert(
						HexBytes::from(k.as_inner().to_vec()),
						HexBytes::from(v.to_vec())
					);
				}
				hash160_map
			},
		    hash256_preimages: {
				let mut hash256_map = HashMap::new();
				for (k, v) in &self.hash256_preimages{
					hash256_map.insert(
						HexBytes::from(k.as_inner().to_vec()),
						HexBytes::from(v.to_vec())
					);
				}
				hash256_map
			},
		    previous_txid: HexBytes::from(self.previous_txid.as_inner().to_vec()),
		    previous_output_index: self.previous_output_index,
		    sequence: self.sequence.unwrap_or(0xffffffff),
		    required_time_locktime: self.required_time_locktime,
		    required_height_locktime: self.required_height_locktime,
		    issuance_value:
				self.issuance_value.as_ref().map(|x| x.get_info(network)),
		    issuance_value_rangeproof:
				self.issuance_value_rangeproof.as_ref().map(|v| HexBytes::from(v.clone())),
		    issuance_keys_rangeproof:
				self.issuance_keys_rangeproof.as_ref().map(|v| HexBytes::from(v.clone())),
		    pegin_tx: self.pegin_tx.as_ref().map(|tx| HexBytes::from(encode::serialize(tx))),
		    pegin_txout_proof:
				self.pegin_txout_proof.as_ref().map(|v| HexBytes::from(v.clone())),
		    pegin_genesis_hash: self.pegin_genesis_hash.map(|x| HexBytes::from(x.as_inner().to_vec())),
		    pegin_claim_script:
				self.pegin_claim_script.as_ref().map(|x| ::tx::InputScript(x).get_info(network)),
		    pegin_value: self.pegin_value,
		    pegin_witness: self.pegin_witness.as_ref()
				.map(|w| w.iter().map(|p| p.clone().into()).collect()),
		    issuance_inflation_keys:
				self.issuance_inflation_keys.as_ref().map(|x| x.get_info(network)),
		    issuance_blinding_nonce:
				self.issuance_blinding_nonce.map(|x| HexBytes::from(encode::serialize(&x))),
		    issuance_asset_entropy:
				self.issuance_asset_entropy.map(|x| HexBytes::from(encode::serialize(&x))),
			proprietary: {
				let mut proprietary = HashMap::new();
				for (k, v) in &self.proprietary {
					proprietary.insert(
						HexBytes::from(encode::serialize(&k.to_key())),
						HexBytes::from(v.to_vec()),
					);
				}
				proprietary
			},
			unknown: {
				let mut unknown = HashMap::new();
				for (k, v) in &self.unknown {
					unknown.insert(
						HexBytes::from(encode::serialize(k)),
						HexBytes::from(v.to_vec()),
					);
				}
				unknown
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsetOutputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<::tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<::HexBytes, HDPathInfo>,
	pub amount: ::confidential::ConfidentialValueInfo,
	pub script_pubkey: ::tx::OutputScriptInfo,
	pub asset: ::confidential::ConfidentialAssetInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub value_rangeproof: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub asset_surjection_proof: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub blinding_key: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ecdh_pubkey: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub blinder_index: Option<u32>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub proprietary: HashMap<::HexBytes, ::HexBytes>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
    pub unknown: HashMap<::HexBytes, ::HexBytes>,
}

impl ::GetInfo<PsetOutputInfo> for pset::Output {
	fn get_info(&self, network: Network) -> PsetOutputInfo {
		PsetOutputInfo {
			redeem_script: self.redeem_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| ::tx::OutputScript(s).get_info(network)),
			hd_keypaths: {
				let mut hd_keypaths = HashMap::new();
				for (key, value) in self.bip32_derivation.iter() {
					hd_keypaths.insert(key.to_bytes().into(),
						HDPathInfo {
							master_fingerprint: value.0[..].into(),
							path: value.1.clone(),
						},
					);
				}
				hd_keypaths
			},
		    amount: self.amount.get_info(network),
		    script_pubkey: ::tx::OutputScript(&self.script_pubkey).get_info(network),
		    asset: self.asset.get_info(network),
		    value_rangeproof:
				self.value_rangeproof.as_ref().map(|v| HexBytes::from(v.clone())),
		    asset_surjection_proof:
				self.asset_surjection_proof.as_ref().map(|v| HexBytes::from(v.clone())),
		    blinding_key:
				self.blinding_key.map(|x| HexBytes::from(x.to_bytes())),
		    ecdh_pubkey:
				self.ecdh_pubkey.map(|x| HexBytes::from(x.to_bytes())),
		    blinder_index: self.blinder_index,
			proprietary: {
				let mut proprietary = HashMap::new();
				for (k, v) in &self.proprietary {
					proprietary.insert(
						HexBytes::from(encode::serialize(&k.to_key())),
						HexBytes::from(v.to_vec()),
					);
				}
				proprietary
			},
			unknown: {
				let mut unknown = HashMap::new();
				for (k, v) in &self.unknown {
					unknown.insert(
						HexBytes::from(encode::serialize(k)),
						HexBytes::from(v.to_vec()),
					);
				}
				unknown
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsetInfo {
	pub global: PsetGlobalInfo,
	pub inputs: Vec<PsetInputInfo>,
	pub outputs: Vec<PsetOutputInfo>,
}

impl ::GetInfo<PsetInfo> for pset::PartiallySignedTransaction {
	fn get_info(&self, network: Network) -> PsetInfo {
		PsetInfo {
			global: self.global.get_info(network),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}
