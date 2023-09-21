use std::io::Write;

use elements::encode::{deserialize, serialize};
use elements::{dynafed, Block, BlockExtData, BlockHeader};

use cmd;
use cmd::tx::create_transaction;
use hal_elements::block::{BlockHeaderInfo, BlockInfo, ParamsInfo, ParamsType};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("block", "manipulate blocks")
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
	cmd::subcommand("create", "create a raw block from JSON").args(&[
		cmd::arg("block-info", "the block info in JSON").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn create_params(info: ParamsInfo) -> dynafed::Params {
	match info.params_type {
		ParamsType::Null => dynafed::Params::Null,
		ParamsType::Compact => dynafed::Params::Compact {
			signblockscript: info
				.signblockscript
				.expect("signblockscript missing in compact params")
				.0
				.into(),
			signblock_witness_limit: info
				.signblock_witness_limit
				.expect("signblock_witness_limit missing in compact params"),
			elided_root: info.elided_root.expect("elided_root missing in compact params"),
		},
		ParamsType::Full => todo!("ELEMENTS BUG: Fullparams is not public")
		// dynafed::Params::Full(FullParams {
		// 	signblockscript: info
		// 		.signblockscript
		// 		.expect("signblockscript missing in full params")
		// 		.0
		// 		.into(),
		// 	signblock_witness_limit: info
		// 		.signblock_witness_limit
		// 		.expect("signblock_witness_limit missing in full params"),
		// 	fedpeg_program: info
		// 		.fedpeg_program
		// 		.expect("fedpeg_program missing in full params")
		// 		.0
		// 		.into(),
		// 	fedpegscript: info.fedpeg_script.expect("fedpeg_script missing in full params").0,
		// 	extension_space: info
		// 		.extension_space
		// 		.expect("extension space missing in full params")
		// 		.into_iter()
		// 		.map(|b| b.0)
		// 		.collect(),
		// }),
	}
}

fn create_block_header(info: BlockHeaderInfo) -> BlockHeader {
	if info.block_hash.is_some() {
		warn!("Field \"block_hash\" is ignored.");
	}

	BlockHeader {
		version: info.version,
		prev_blockhash: info.previous_block_hash,
		merkle_root: info.merkle_root,
		time: info.time,
		height: info.height,
		ext: if info.dynafed {
			BlockExtData::Dynafed {
				current: create_params(info.dynafed_current.expect("missing current params")),
				proposed: create_params(info.dynafed_proposed.expect("missing proposed params")),
				signblock_witness: info
					.dynafed_witness
					.expect("missing dynafed witness")
					.into_iter()
					.map(|b| b.0)
					.collect(),
			}
		} else {
			BlockExtData::Proof {
				challenge: info.legacy_challenge.expect("missing challenge").0.into(),
				solution: info.legacy_solution.expect("missing solution").0.into(),
			}
		},
	}
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let json_block = matches.value_of("block-info").expect("no JSON blok info provided");
	let info: BlockInfo = serde_json::from_str(json_block).expect("invalid JSON");

	if info.txids.is_some() {
		warn!("Field \"txids\" is ignored.");
	}

	let block = Block {
		header: create_block_header(info.header),
		txdata: match (info.transactions, info.raw_transactions) {
			(Some(_), Some(_)) => panic!("Can't provide transactions both in JSON and raw."),
			(None, None) => panic!("No transactions provided."),
			(Some(infos), None) => infos.into_iter().map(create_transaction).collect(),
			(None, Some(raws)) => raws
				.into_iter()
				.map(|r| deserialize(&r.0).expect("invalid raw transaction"))
				.collect(),
		},
	};

	let block_bytes = serialize(&block);
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&block_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&block_bytes));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a raw block to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("raw-block", "the raw block in hex").required(true),
		cmd::opt("txids", "provide transactions IDs instead of full transactions"),
	])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-block").expect("no raw block provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw block hex");
	let block: Block = deserialize(&raw_tx).expect("invalid block format");

	if matches.is_present("txids") {
		let info = BlockInfo {
			header: ::GetInfo::get_info(&block.header, cmd::network(matches)),
			txids: Some(block.txdata.iter().map(|t| t.txid()).collect()),
			transactions: None,
			raw_transactions: None,
		};
		cmd::print_output(matches, &info)
	} else {
		let info = ::GetInfo::get_info(&block, cmd::network(matches));
		cmd::print_output(matches, &info)
	}
}
