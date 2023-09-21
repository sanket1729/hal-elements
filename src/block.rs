use elements::hashes::{sha256, Hash};
use elements::{BlockHash, TxMerkleNode, Txid};
use elements::{dynafed, Block, BlockExtData, BlockHeader};
use serde::{Deserialize, Serialize};

use ::{GetInfo, Network, HexBytes};

use tx::TransactionInfo;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamsType {
	Null,
	Compact,
	Full,
}

impl Default for ParamsType {
	fn default() -> ParamsType {
		ParamsType::Null
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct ParamsInfo {
	pub params_type: ParamsType,
	// both
	pub signblockscript: Option<HexBytes>,
	pub signblock_witness_limit: Option<u32>,
	// compact only
	#[serde(skip_serializing_if = "Option::is_none")]
	pub elided_root: Option<sha256::Midstate>,
	// full only
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fedpeg_program: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fedpeg_script: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub extension_space: Option<Vec<HexBytes>>,
}

impl<'a> GetInfo<ParamsInfo> for dynafed::Params {
	fn get_info(&self, _network: Network) -> ParamsInfo {
		ParamsInfo {
			params_type: match self {
				dynafed::Params::Null => ParamsType::Null,
				dynafed::Params::Compact {
					..
				} => ParamsType::Compact,
				dynafed::Params::Full {
					..
				} => ParamsType::Full,
			},
			signblockscript: self.signblockscript().map(|s| s.to_bytes().into()),
			signblock_witness_limit: self.signblock_witness_limit(),
			elided_root: self.elided_root().map(|r| *r),
			fedpeg_program: self.fedpeg_program().map(|p| p.as_bytes().into()),
			fedpeg_script: self.fedpegscript().map(|s| s[..].into()),
			extension_space: self
				.extension_space()
				.map(|s| s.iter().map(|v| v[..].into()).collect()),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockHeaderInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub block_hash: Option<BlockHash>,
	pub version: u32,
	pub previous_block_hash: BlockHash,
	pub merkle_root: TxMerkleNode,
	pub time: u32,
	pub height: u32,
	pub dynafed: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub legacy_challenge: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub legacy_solution: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dynafed_current: Option<ParamsInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dynafed_proposed: Option<ParamsInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dynafed_witness: Option<Vec<HexBytes>>,
}

impl Default for BlockHeaderInfo {
    fn default() -> Self {
        Self {
			previous_block_hash: BlockHash::all_zeros(),
			merkle_root: TxMerkleNode::all_zeros(),
            block_hash: None,
            version: 0,
            time: 0,
            height: 0,
            dynafed: false,
            legacy_challenge: None,
            legacy_solution: None,
            dynafed_current: None,
            dynafed_proposed: None,
            dynafed_witness: None,
		}
    }
}

impl<'a> GetInfo<BlockHeaderInfo> for BlockHeader {
	fn get_info(&self, network: Network) -> BlockHeaderInfo {
		let mut info = BlockHeaderInfo {
			block_hash: Some(self.block_hash()),
			version: self.version,
			previous_block_hash: self.prev_blockhash,
			merkle_root: self.merkle_root,
			time: self.time,
			height: self.height,
			..Default::default()
		};
		match self.ext {
			BlockExtData::Proof {
				ref challenge,
				ref solution,
			} => {
				info.dynafed = false;
				info.legacy_challenge = Some(challenge.to_bytes().into());
				info.legacy_solution = Some(solution.to_bytes().into());
			}
			BlockExtData::Dynafed {
				ref current,
				ref proposed,
				ref signblock_witness,
			} => {
				info.dynafed = true;
				info.dynafed_current = Some(current.get_info(network));
				info.dynafed_proposed = Some(proposed.get_info(network));
				info.dynafed_witness =
					Some(signblock_witness.iter().map(|b| b[..].into()).collect());
			}
		};
		info
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockInfo {
	pub header: BlockHeaderInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transactions: Option<Vec<TransactionInfo>>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub txids: Option<Vec<Txid>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_transactions: Option<Vec<HexBytes>>,
}

impl GetInfo<BlockInfo> for Block {
	fn get_info(&self, network: Network) -> BlockInfo {
		BlockInfo {
			header: self.header.get_info(network),
			transactions: Some(self.txdata.iter().map(|t| t.get_info(network)).collect()),
			txids: None,
			raw_transactions: None,
		}
	}
}
