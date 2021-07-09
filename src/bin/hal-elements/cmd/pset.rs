use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use base64;
use clap;
use hex;

use elements::secp256k1_zkp;
use bitcoin::util::bip32;
use elements::{pset, Transaction, confidential};
use elements::pset::PartiallySignedTransaction as Pset;
use bitcoin::{self, PrivateKey, PublicKey};
use elements::encode::{serialize, deserialize};
use miniscriptlib;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("pset", "partially signed Elements transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_edit())
		.subcommand(cmd_finalize())
		.subcommand(cmd_merge())
		.subcommand(cmd_rawsign())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		("edit", Some(ref m)) => exec_edit(&m),
		("finalize", Some(ref m)) => exec_finalize(&m),
		("merge", Some(ref m)) => exec_merge(&m),
		("rawsign", Some(ref m)) => exec_rawsign(&m),
		(c, _) => eprintln!("command {} unknown", c),
	};
}

#[derive(Debug)]
enum PsetSource {
	Base64,
	Hex,
	File,
}

/// Tries to decode the string as hex and base64, if it works, returns the bytes.
/// If not, tries to open a filename with the given string as relative path, if it works, returns
/// the content bytes.
/// Also returns an enum value indicating which source worked.
fn file_or_raw(flag: &str) -> (Vec<u8>, PsetSource) {
	if let Ok(raw) = hex::decode(&flag) {
		(raw, PsetSource::Hex)
	} else if let Ok(raw) = base64::decode(&flag) {
		(raw, PsetSource::Base64)
	} else if let Ok(mut file) = File::open(&flag) {
		let mut buf = Vec::new();
		file.read_to_end(&mut buf).expect("error reading file");
		(buf, PsetSource::File)
	} else {
		panic!("Can't load PSET: invalid hex, base64 or unknown file");
	}
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSET from an unsigned raw transaction").args(&[
		cmd::arg("raw-tx", "the raw transaction in hex").required(true),
		cmd::opt("output", "where to save the merged PSET output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let pset = Pset::from_tx(tx);

	let serialized = serialize(&pset);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&serialized).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&serialized).unwrap();
	} else {
		print!("{}", base64::encode(&serialized));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSET to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("pset", "the PSET file or raw PSET in base64/hex").required(true),
	])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw_pset, _) = file_or_raw(matches.value_of("pset").unwrap());

	let pset: pset::PartiallySignedTransaction = deserialize(&raw_pset).expect("invalid PSET");

	let info = hal_elements::GetInfo::get_info(&pset, cmd::network(matches));
	cmd::print_output(matches, &info)
}

fn cmd_edit<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("edit", "edit a PSET").args(&[
		cmd::arg("pset", "PSET to edit, either base64/hex or a file path").required(true),
		cmd::opt("input-idx", "the input index to edit")
			.display_order(1)
			.takes_value(true)
			.required(false),
		cmd::opt("output-idx", "the output index to edit")
			.display_order(2)
			.takes_value(true)
			.required(false),
		cmd::opt("output", "where to save the resulting PSET file -- in place if omitted")
			.short("o")
			.display_order(3)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		//
		// values used in both inputs and outputs
		cmd::opt("redeem-script", "the redeem script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-script", "the witness script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths", "the HD wallet keypaths `<pubkey>:<master-fp>:<path>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths-add", "add an HD wallet keypath `<pubkey>:<master-fp>:<path>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// input values
		cmd::opt("non-witness-utxo", "the non-witness UTXO field in hex (full transaction)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-utxo", "the witness UTXO field in hex (only output)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs", "set partial sigs `<pubkey>:<signature>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs-add", "add a partial sig pair `<pubkey>:<signature>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("sighash-type", "the sighash type")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
		cmd::opt("final-script-sig", "set final script signature")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("final-script-witness", "set final script witness as comma-separated hex values")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// output values
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
	])
}

/// Parses a `<pubkey>:<signature>` pair.
fn parse_partial_sig_pair(pair_str: &str) -> (PublicKey, Vec<u8>) {
	let mut pair = pair_str.splitn(2, ":");
	let pubkey = pair.next().unwrap().parse().expect("invalid partial sig pubkey");
	let sig = {
		let hex = pair.next().expect("invalid partial sig pair: missing signature");
		hex::decode(&hex).expect("invalid partial sig signature hex")
	};
	(pubkey, sig)
}

fn parse_hd_keypath_triplet(
	triplet_str: &str,
) -> (PublicKey, (bip32::Fingerprint, bip32::DerivationPath)) {
	let mut triplet = triplet_str.splitn(3, ":");
	let pubkey = triplet.next().unwrap().parse().expect("invalid HD keypath pubkey");
	let fp = {
		let hex = triplet.next().expect("invalid HD keypath triplet: missing fingerprint");
		let raw = hex::decode(&hex).expect("invalid HD keypath fingerprint hex");
		if raw.len() != 4 {
			panic!("invalid HD keypath fingerprint size: {} instead of 4", raw.len());
		}
		raw[..].into()
	};
	let path = triplet
		.next()
		.expect("invalid HD keypath triplet: missing HD path")
		.parse()
		.expect("invalid derivation path format");
	(pubkey, (fp, path))
}

fn edit_input<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	pset: &mut pset::PartiallySignedTransaction,
) {
	let input = pset.inputs.get_mut(idx).expect("input index out of range");

	if let Some(hex) = matches.value_of("non-witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid non-witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid non-witness-utxo transaction");
		input.non_witness_utxo = Some(utxo);
	}

	if let Some(hex) = matches.value_of("witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid witness-utxo transaction");
		input.witness_utxo = Some(utxo);
	}

	if let Some(csv) = matches.value_of("partial-sigs") {
		input.partial_sigs = csv.split(",").map(parse_partial_sig_pair).collect();
	}
	if let Some(pairs) = matches.values_of("partial-sigs-add") {
		for (pk, sig) in pairs.map(parse_partial_sig_pair) {
			if input.partial_sigs.insert(pk, sig).is_some() {
				panic!("public key {} is already in partial sigs", &pk);
			}
		}
	}

	if let Some(sht) = matches.value_of("sighash-type") {
		input.sighash_type = Some(hal_elements::pset::sighashtype_from_string(&sht));
	}

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		input.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		input.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		input.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if input.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}

	if let Some(hex) = matches.value_of("final-script-sig") {
		let raw = hex::decode(&hex).expect("invalid final-script-sig hex");
		input.final_script_sig = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("final-script-witness") {
		let vhex = csv.split(",");
		let vraw = vhex.map(|h| hex::decode(&h).expect("invalid final-script-witness hex"));
		input.final_script_witness = Some(vraw.collect());
	}
}

fn edit_output<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	pset: &mut pset::PartiallySignedTransaction,
) {
	let output = pset.outputs.get_mut(idx).expect("output index out of range");

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		output.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		output.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		output.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if output.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}
}

fn exec_edit<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = file_or_raw(&matches.value_of("pset").unwrap());
	let mut pset: pset::PartiallySignedTransaction =
		deserialize(&raw).expect("invalid PSET format");

	match (matches.value_of("input-idx"), matches.value_of("output-idx")) {
		(None, None) => panic!("no input or output index provided"),
		(Some(_), Some(_)) => panic!("can only edit an input or an output at a time"),
		(Some(idx), _) => {
			edit_input(idx.parse().expect("invalid input index"), &matches, &mut pset)
		}
		(_, Some(idx)) => {
			edit_output(idx.parse().expect("invalid output index"), &matches, &mut pset)
		}
	}

	let edited_raw = serialize(&pset);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&edited_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&edited_raw).unwrap();
	} else {
		match source {
			PsetSource::Hex => print!("{}", hex::encode(&edited_raw)),
			PsetSource::Base64 => print!("{}", base64::encode(&edited_raw)),
			PsetSource::File => {
				let path = matches.value_of("pset").unwrap();
				let mut file = File::create(&path).expect("failed to PSET file for writing");
				file.write_all(&edited_raw).expect("error writing PSET file");
			}
		}
	}
}

fn cmd_finalize<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("finalize", "finalize a PSET and print the fully signed tx in hex").args(&[
		cmd::arg("pset", "PSET to finalize, either base64/hex or a file path").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_finalize<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, _) = file_or_raw(&matches.value_of("pset").unwrap());
	let mut pset: pset::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSET format");


	// Create a secp context, should there be one with static lifetime?
	let secp = secp256k1_zkp::Secp256k1::verification_only();
	::miniscriptlib::pset::finalize(&mut pset, &secp).expect("failed to finalize");

	let finalized_raw = serialize(&pset.extract_tx().expect("Unable to extract tx"));
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&finalized_raw).unwrap();
	} else {
		print!("{}", ::hex::encode(&finalized_raw));
	}
}

fn cmd_merge<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("merge", "merge multiple PSET files into one").args(&[
		cmd::arg("psets", "PSETs to merge; can be file paths or base64/hex")
			.multiple(true)
			.required(true),
		cmd::opt("output", "where to save the merged PSET output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_merge<'a>(matches: &clap::ArgMatches<'a>) {
	let mut parts = matches.values_of("psets").unwrap().map(|f| {
		let (raw, _) = file_or_raw(&f);
		let pset: pset::PartiallySignedTransaction =
			deserialize(&raw).expect("invalid PSET format");
		pset
	});

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		// merge function checks if the psets are merge-able.
		merged.merge(part).expect(&format!("error merging PSET #{}", idx));
	}

	let merged_raw = serialize(&merged);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&merged_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&merged_raw).unwrap();
	} else {
		print!("{}", base64::encode(&merged_raw));
	}
}

fn cmd_rawsign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("rawsign", "sign a pset with private key and add sig to partial sigs").args(&[
		cmd::arg("pset", "PSET to finalize, either base64/hex or a file path").required(true),
		cmd::arg("input-idx", "the input index to edit").required(true),
		cmd::arg("priv-key", "the private key in WIF/hex").required(true),
		cmd::arg("compressed", "Whether the corresponding pk is compressed")
			.required(false)
			.default_value("true"),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		cmd::opt("output", "where to save the resulting PSET file -- in place if omitted")
			.short("o")
			.takes_value(true)
			.required(false),
	])
}

// Get the scriptpubkey/amount for the pset input
fn get_spk_amt(pset: &pset::PartiallySignedTransaction, index: usize) -> (&elements::Script, confidential::Value) {
	let script_pubkey;
	let amt;
	let inp = &pset.inputs[index];
	if let Some(ref witness_utxo) = inp.witness_utxo {
		script_pubkey = &witness_utxo.script_pubkey;
		amt = witness_utxo.value;
	} else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
		let vout = pset.inputs[index].previous_output_index;
		script_pubkey = &non_witness_utxo.output[vout as usize].script_pubkey;
		amt = non_witness_utxo.output[vout as usize].value;
	} else {
		panic!("Pset missing both witness and non-witness utxo")
	}
	(script_pubkey, amt)
}

fn exec_rawsign<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = file_or_raw(&matches.value_of("pset").unwrap());
	let mut pset: pset::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSET format");

	let priv_key = matches.value_of("priv-key").expect("no key provided");
	let i = matches.value_of("input-idx").expect("Input index not provided")
		.parse::<usize>().expect("input-idx must be a positive integer");
	let compressed = matches.value_of("compressed").unwrap()
		.parse::<bool>().expect("Compressed must be boolean");

	if i >= pset.inputs.len() {
		panic!("Pset input index out of range")
	}
	let (spk, amt) = get_spk_amt(&pset, i);
	let redeem_script = pset.inputs[i].redeem_script.as_ref().map(|x|
		elements::script::Builder::new()
		.push_slice(x.as_bytes())
		.into_script());
	let witness_script = pset.inputs[i].witness_script.as_ref()
		.map(|x| vec![x.clone().into_bytes()]);
	let witness = witness_script.unwrap_or(Vec::new());
	let script_sig = redeem_script.unwrap_or(elements::Script::new());

	// Call with age and height 0.
	// TODO: Create a method to rust-bitcoin pset that outputs sighash
	// Workaround using miniscript interpreter
	let interp = miniscriptlib::Interpreter::from_txdata(spk, &script_sig, &witness, 0, 0)
		.expect("Witness/Redeem Script is not a Miniscript");
	let sighash_ty = pset.inputs[i].sighash_type.unwrap_or(elements::SigHashType::All);
	let tx = pset.extract_tx().expect("Unable to extract tx");
	let msg = interp.sighash_message(&tx, i, amt, sighash_ty);

	let sk = if let Ok(privkey) = PrivateKey::from_str(&priv_key) {
		privkey.key
	} else if let Ok(sk) = secp256k1_zkp::SecretKey::from_str(&priv_key) {
		sk
	} else {
		panic!("invalid WIF/hex private key: {}", priv_key);
	};
	let secp = secp256k1_zkp::Secp256k1::signing_only();
	let pk = secp256k1_zkp::PublicKey::from_secret_key(&secp, &sk);
	let pk = bitcoin::PublicKey {
		compressed: compressed,
		key: pk,
	};
	let secp_sig = secp.sign(&msg, &sk);
	let mut btc_sig = secp_sig.serialize_der().as_ref().to_vec();
	btc_sig.push(sighash_ty as u8);

	// mutate the pset
	pset.inputs[i].partial_sigs.insert(pk, btc_sig);
	let raw = serialize(&pset);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&raw).unwrap();
	} else {
		match source {
			PsetSource::Hex => println!("{}", hex::encode(&raw)),
			PsetSource::Base64 => println!("{}", base64::encode(&raw)),
			PsetSource::File => {
				let path = matches.value_of("pset").unwrap();
				let mut file = File::create(&path).expect("failed to PSET file for writing");
				file.write_all(&raw).expect("error writing PSET file");
			}
		}
	}
}