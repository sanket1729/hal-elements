use std::io::Write;

use clap;
use bitcoin;
use elements::{hashes::Hash, secp256k1_zkp::{RangeProof, SurjectionProof}};
use elements::Script;
use elements::secp256k1_zkp;
use elements::encode::{deserialize, serialize};
use elements::{
	confidential, AssetIssuance, OutPoint, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness,
};

use cmd;
use hal_elements::tx::{InputScriptInfo, OutputScriptInfo};
use hal_elements::confidential::{
	ConfidentialAssetInfo, ConfidentialNonceInfo, ConfidentialType, ConfidentialValueInfo,
};
use hal_elements::Network;
use hal_elements::tx::{
	AssetIssuanceInfo, InputInfo, InputWitnessInfo, OutputInfo, OutputWitnessInfo, PeginDataInfo,
	PegoutDataInfo, TransactionInfo,
};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("tx", "manipulate transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a raw transaction from JSON").args(&[
		cmd::arg("tx-info", "the transaction info in JSON").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

/// Check both ways to specify the outpoint and panic if conflicting.
fn outpoint_from_input_info(input: &InputInfo) -> OutPoint {
	let op1: Option<OutPoint> =
		input.prevout.as_ref().map(|ref op| op.parse().expect("invalid prevout format"));
	let op2 = match input.txid {
		Some(txid) => match input.vout {
			Some(vout) => Some(OutPoint {
				txid: txid,
				vout: vout,
			}),
			None => panic!("\"txid\" field given in input without \"vout\" field"),
		},
		None => None,
	};

	match (op1, op2) {
		(Some(op1), Some(op2)) => {
			if op1 != op2 {
				panic!("Conflicting prevout information in input.");
			}
			op1
		}
		(Some(op), None) => op,
		(None, Some(op)) => op,
		(None, None) => panic!("No previous output provided in input."),
	}
}

fn bytes_32(bytes: &[u8]) -> Option<[u8; 32]> {
	if bytes.len() != 32 {
		None
	} else {
		let mut array = [0; 32];
		for (x, y) in bytes.iter().zip(array.iter_mut()) {
			*y = *x;
		}
		Some(array)
	}
}


fn create_confidential_value(info: ConfidentialValueInfo) -> confidential::Value {
	match info.type_ {
		ConfidentialType::Null => confidential::Value::Null,
		ConfidentialType::Explicit => confidential::Value::Explicit(
			info.value.expect("Field \"value\" is required for explicit values."),
		),
		ConfidentialType::Confidential => {
			let comm = secp256k1_zkp::PedersenCommitment::from_slice(
				info.commitment.expect("Missing commitment").bytes()
			).expect("Invalid Confidential commitment");
			confidential::Value::Confidential(comm)
		}
	}
}

fn create_confidential_asset(info: ConfidentialAssetInfo) -> confidential::Asset {
	match info.type_ {
		ConfidentialType::Null => confidential::Asset::Null,
		ConfidentialType::Explicit => confidential::Asset::Explicit(
			info.asset.expect("Field \"asset\" is required for explicit assets."),
		),
		ConfidentialType::Confidential => {
			let gen = secp256k1_zkp::Generator::from_slice(
				info.commitment.expect("Missing asset commitment").bytes()
			).expect("Invalid asset commitment");
			confidential::Asset::Confidential(gen)
		}
	}
}

fn create_confidential_nonce(info: ConfidentialNonceInfo) -> confidential::Nonce {
	match info.type_ {
		ConfidentialType::Null => confidential::Nonce::Null,
		ConfidentialType::Explicit => confidential::Nonce::Explicit(
			info.nonce.expect("Field \"nonce\" is required for explicit nonces.").to_byte_array(),
		),
		ConfidentialType::Confidential => {
			let comm = secp256k1_zkp::PublicKey::from_slice(
				info.commitment.expect("Missing nonce commitment").bytes()
			).expect("Invalid Nonce Pubkey");
			confidential::Nonce::Confidential(comm)
		}
	}
}

fn create_asset_issuance(info: AssetIssuanceInfo) -> AssetIssuance {
	AssetIssuance {
		asset_blinding_nonce: secp256k1_zkp::Tweak::from_slice(
			&info
				.asset_blinding_nonce
				.expect("Field \"asset_blinding_nonce\" is required for asset issuances.")
				.0[..],
		)
		.expect("Invalid size of \"asset_blinding_nonce\" or blinding nonce out of range"),
		asset_entropy: bytes_32(
			&info
				.asset_entropy
				.expect("Field \"asset_entropy\" is required for asset issuances.")
				.0[..],
		)
		.expect("Invalid size of \"asset_entropy\"."),
		amount: create_confidential_value(
			info.amount.expect("Field \"amount\" is required for asset issuances."),
		),
		inflation_keys: create_confidential_value(
			info.inflation_keys.expect("Field \"inflation_keys\" is required for asset issuances."),
		),
	}
}

fn create_script_sig(ss: InputScriptInfo) -> Script {
	if let Some(hex) = ss.hex {
		if ss.asm.is_some() {
			warn!("Field \"asm\" of input is ignored.");
		}

		hex.0.into()
	} else if let Some(_) = ss.asm {
		panic!("Decoding script assembly is not yet supported.");
	} else {
		panic!("No scriptSig info provided.");
	}
}

fn create_pegin_witness(pd: PeginDataInfo, prevout: bitcoin::OutPoint) -> Vec<Vec<u8>> {
	let btc_prev = bitcoin::OutPoint::new(prevout.txid, prevout.vout);
	if btc_prev != pd.outpoint.parse().expect("Invalid outpoint in field \"pegin_data\".") {
		panic!("Outpoint in \"pegin_data\" does not correspond to input value.");
	}

	let asset = match create_confidential_asset(pd.asset) {
		confidential::Asset::Explicit(asset) => asset,
		_ => panic!("Asset in \"pegin_data\" should be explicit."),
	};
	vec![
		serialize(&pd.value),
		serialize(&asset),
		serialize(&pd.genesis_hash),
		serialize(&pd.claim_script.0),
		serialize(&pd.mainchain_tx_hex.0),
		serialize(&pd.merkle_proof.0),
	]
}

fn create_input_witness(
	info: Option<InputWitnessInfo>,
	pd: Option<PeginDataInfo>,
	prevout: bitcoin::OutPoint,
) -> TxInWitness {
	let pegin_witness = if info.is_some() && info.as_ref().unwrap().pegin_witness.is_some() {
		if pd.is_some() {
			warn!("Field \"pegin_data\" of input is ignored.");
		}
		info.as_ref().unwrap().pegin_witness.clone().unwrap().iter().map(|h| h.clone().0).collect()
	} else if let Some(pd) = pd {
		create_pegin_witness(pd, prevout)
	} else {
		Default::default()
	};

	if let Some(wi) = info {
		TxInWitness {
			amount_rangeproof: wi.amount_rangeproof
				.map(|ref x| Box::new(RangeProof::from_slice(x.bytes()).expect("Invalid RangeProof"))),
			inflation_keys_rangeproof: wi
				.inflation_keys_rangeproof
				.map(|ref x| Box::new(RangeProof::from_slice(x.bytes()).expect("Invalid RangeProof"))),
			script_witness: match wi.script_witness {
				Some(ref w) => w.iter().map(|h| h.clone().0).collect(),
				None => Vec::new(),
			},
			pegin_witness: pegin_witness,
		}
	} else {
		TxInWitness {
			pegin_witness: pegin_witness,
			..Default::default()
		}
	}
}

fn create_input(input: InputInfo) -> TxIn {
	let has_issuance = input.has_issuance.unwrap_or(input.asset_issuance.is_some());
	let is_pegin = input.is_pegin.unwrap_or(input.pegin_data.is_some());
	let prevout = outpoint_from_input_info(&input);

	TxIn {
		previous_output: prevout,
		script_sig: input.script_sig.map(create_script_sig).unwrap_or_default(),
		sequence: input.sequence.unwrap_or_default(),
		is_pegin: is_pegin,
		asset_issuance: if has_issuance {
			input.asset_issuance.map(create_asset_issuance).unwrap_or_default()
		} else {
			if input.asset_issuance.is_some() {
				warn!("Field \"asset_issuance\" of input is ignored.");
			}
			Default::default()
		},
		witness: {
			let btc_prevout = bitcoin::OutPoint::new(
				bitcoin::Txid::from_raw_hash(prevout.txid.into()),
				 prevout.vout
			);
			create_input_witness(input.witness, input.pegin_data, btc_prevout)
		}
	}
}

fn create_pegout_script_pubkey(spk: hal::tx::OutputScriptInfo) -> bitcoin::ScriptBuf {
	if spk.type_.is_some() {
		warn!("Field \"type\" of output is ignored.");
	}

	if let Some(hex) = spk.hex {
		if spk.asm.is_some() {
			warn!("Field \"asm\" of output is ignored.");
		}
		if spk.address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		//TODO(stevenroose) do script sanity check to avoid blackhole?
		hex.0.into()
	} else if let Some(_) = spk.asm {
		if spk.address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		//TODO(stevenroose) support script disassembly
		panic!("Decoding script assembly is not yet supported.");
	} else if let Some(address) = spk.address {
		address.assume_checked().script_pubkey()
	} else {
		panic!("No scriptPubKey info provided.");
	}
}

fn create_script_pubkey(spk: OutputScriptInfo, used_network: &mut Option<Network>) -> Script {
	if spk.type_.is_some() {
		warn!("Field \"type\" of output is ignored.");
	}

	if let Some(hex) = spk.hex {
		if spk.asm.is_some() {
			warn!("Field \"asm\" of output is ignored.");
		}
		if spk.unblinded_address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		//TODO(stevenroose) do script sanity check to avoid blackhole?
		hex.0.into()
	} else if let Some(_) = spk.asm {
		if spk.unblinded_address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		panic!("Decoding script assembly is not yet supported.");
	} else if let Some(address) = spk.unblinded_address {
		// Error if another network had already been used.
		let net = Network::from_params(address.params).expect("Unknown address");
		if used_network.replace(net)
			.unwrap_or(net) != net {
			panic!("Addresses for different networks are used in the output scripts.");
		}

		address.script_pubkey()
	} else {
		panic!("No scriptPubKey info provided.");
	}
}

fn create_output_witness(w: OutputWitnessInfo) -> TxOutWitness {
	TxOutWitness {
		surjection_proof: w.surjection_proof
			.map(|ref x| Box::new(SurjectionProof::from_slice(x.bytes())
			.expect("Invalid SurjectionProof"))),
		rangeproof: w.rangeproof
			.map(|ref x| Box::new(RangeProof::from_slice(x.bytes())
			.expect("Invalid RangeProof"))),
	}
}

// The network used is the bitcoin Network
// so we do not maintain the network on the &mut used_network
fn create_script_pubkey_from_pegout_data(
	pd: PegoutDataInfo,
) -> Script {
	let mut builder = elements::script::Builder::new()
		.push_opcode(elements::opcodes::all::OP_RETURN)
		.push_slice(&pd.genesis_hash.to_byte_array())
		.push_slice(&create_pegout_script_pubkey(pd.script_pub_key).as_bytes());
	for d in pd.extra_data {
		builder = builder.push_slice(&d.0);
	}
	builder.into_script()
}

fn create_output(output: OutputInfo) -> TxOut {
	// Keep track of which network has been used in addresses and error if two different networks
	// are used.
	let mut used_network = None;
	let value = output
		.value
		.map(create_confidential_value)
		.expect("Field \"value\" is required for outputs.");
	let asset = output
		.asset
		.map(create_confidential_asset)
		.expect("Field \"asset\" is required for outputs.");

	TxOut {
		asset: asset,
		value: value,
		nonce: output.nonce.map(create_confidential_nonce).unwrap_or(confidential::Nonce::Null),
		script_pubkey: if let Some(spk) = output.script_pub_key {
			if output.pegout_data.is_some() {
				warn!("Field \"pegout_data\" of output is ignored.");
			}
			create_script_pubkey(spk, &mut used_network)
		} else if let Some(pd) = output.pegout_data {
			match value {
				confidential::Value::Explicit(v) => {
					if v != pd.value {
						panic!("Value in \"pegout_data\" does not correspond to output value.");
					}
				}
				_ => panic!("Explicit value is required for pegout data."),
			}
			if asset != create_confidential_asset(pd.asset.clone()) {
				panic!("Asset in \"pegout_data\" does not correspond to output value.");
			}
			create_script_pubkey_from_pegout_data(pd)
		} else {
			Default::default()
		},
		witness: output.witness.map(create_output_witness).unwrap_or_default(),
	}
}

pub fn create_transaction(info: TransactionInfo) -> Transaction {
	// Fields that are ignored.
	if info.txid.is_some() {
		warn!("Field \"txid\" is ignored.");
	}
	if info.hash.is_some() {
		warn!("Field \"hash\" is ignored.");
	}
	if info.size.is_some() {
		warn!("Field \"size\" is ignored.");
	}
	if info.weight.is_some() {
		warn!("Field \"weight\" is ignored.");
	}
	if info.vsize.is_some() {
		warn!("Field \"vsize\" is ignored.");
	}

	Transaction {
		version: info.version.expect("Field \"version\" is required."),
		lock_time: info.locktime.expect("Field \"locktime\" is required."),
		input: info
			.inputs
			.expect("Field \"inputs\" is required.")
			.into_iter()
			.map(create_input)
			.collect(),
		output: info
			.outputs
			.expect("Field \"outputs\" is required.")
			.into_iter()
			.map(create_output)
			.collect(),
	}
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let json_tx = matches.value_of("tx-info").expect("no JSON tx info provided");
	let info: TransactionInfo = serde_json::from_str(json_tx).expect("invalid JSON");
	let tx = create_transaction(info);

	let tx_bytes = serialize(&tx);
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&tx_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&tx_bytes));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a raw transaction to JSON")
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml(), cmd::arg("raw-tx", "the raw transaction in hex").required(true)])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let info = ::GetInfo::get_info(&tx, cmd::network(matches));
	cmd::print_output(matches, &info)
}
