pub mod address;
pub mod block;
pub mod tx;
pub mod miniscript;

use hal_elements::Network;

/// Build a list of all built-in subcommands.
pub fn subcommands<'a>() -> Vec<clap::App<'a, 'a>> {
	vec![
		address::subcommand(),
		block::subcommand(),
		tx::subcommand(),
		miniscript::subcommand(),
	]
}

/// Construct a new command option.
pub fn opt<'a>(name: &'static str, help: &'static str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).long(name).help(help)
}

/// Construct a new positional argument.
pub fn arg<'a>(name: &'static str, help: &'static str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).help(help).takes_value(true)
}

/// Create a new subcommand group using the template that sets all the common settings.
/// This is not intended for actual commands, but for subcommands that host a bunch of other
/// subcommands.
pub fn subcommand_group<'a>(name: &'static str, about: &'static str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name)
		.about(about)
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		//.setting(clap::AppSettings::AllowExternalSubcommands)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.setting(clap::AppSettings::VersionlessSubcommands)
}

/// Create a new subcommand using the template that sets all the common settings.
pub fn subcommand<'a>(name: &'static str, about: &'static str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name)
		.about(about)
		.setting(clap::AppSettings::ArgRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
}

pub fn opts_networks<'a>() -> Vec<clap::Arg<'a, 'a>> {
	vec![
		clap::Arg::with_name("elementsregtest")
			.long("elementsregtest")
			.short("r")
			.help("run in elementsregtest mode")
			.takes_value(false)
			.required(false),
		clap::Arg::with_name("liquid")
			.long("liquid")
			.help("run in liquid mode")
			.takes_value(false)
			.required(false),
	]
}

pub fn network<'a>(matches: &clap::ArgMatches<'a>) -> Network {
	if matches.is_present("elementsregtest") {
		Network::ElementsRegtest
	} else if matches.is_present("liquid") {
		Network::Liquid
	} else {
		Network::ElementsRegtest
	}
}

pub fn opt_yaml<'a>() -> clap::Arg<'a, 'a> {
	clap::Arg::with_name("yaml")
		.long("yaml")
		.short("y")
		.help("print output in YAML instead of JSON")
		.takes_value(false)
		.required(false)
}

pub fn print_output<'a, T: serde::Serialize>(matches: &clap::ArgMatches<'a>, out: &T) {
	if matches.is_present("yaml") {
		serde_yaml::to_writer(::std::io::stdout(), &out).unwrap();
	} else {
		serde_json::to_writer_pretty(::std::io::stdout(), &out).unwrap();
	}
}
