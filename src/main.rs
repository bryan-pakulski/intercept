pub mod error;
pub mod net;
pub mod rules;

use clap::{Arg, Command};

use log::{info, LevelFilter};
use error::BackendError;
use net::intercept;
use rules::Rule;

fn main() -> Result<(), BackendError> {
    // Unless overriden by RUST_LOG, set the default log level to info
    if let Ok(log_level) = std::env::var("RUST_LOG") {
        env_logger::builder().parse_filters(&log_level).init();

    } else {
        env_logger::builder().filter_level(LevelFilter::Info).init();
    }

    let matches = Command::new("intercept")
        .version("1.0")
        .about("SIP packet interceptor for header manipulation")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .required(true)
                .help("Input Queue Id")
                .value_name("INPUT"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .required(true)
                .help("Output Queue Id")
                .value_name("OUTPUT"),
        )
        .arg(
            Arg::new("ruleset")
                .short('r')
                .long("ruleset")
                .required(true)
                .help("Path to the ruleset JSON file")
                .value_name("RULESET"),
        )
        .get_matches();

    let input = matches
        .get_one::<String>("input")
        .expect("input queue id is required");
    let output = matches
        .get_one::<String>("output")
        .expect("output queue id is required");
    let ruleset = matches
        .get_one::<String>("ruleset")
        .expect("ruleset is required");

    let art = r#"
    ██╗ ███╗   ██╗ ████████╗ ███████╗ ██████╗   ██████╗ ███████╗ ██████╗  ████████╗
    ██║ ████╗  ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗ ╚══██╔══╝
    ██║ ██╔██╗ ██║    ██║    █████╗   ██████╔╝ ██║      █████╗   ██████╔╝    ██║
    ██║ ██║╚██╗██║    ██║    ██╔══╝   ██╔══██╗ ██║      ██╔══╝   ██╔═══╝     ██║
    ██║ ██║ ╚████║    ██║    ███████╗ ██║  ██║ ╚██████╗ ███████╗ ██║         ██║
    ╚═╝ ╚═╝  ╚═══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝  ╚═════╝ ╚══════╝ ╚═╝         ╚═╝
    "#;

    info!("{}", art);
    info!(
        "in queue: {}   ==   out queue: {}   ==   ruleset: {}",
        input, output, ruleset
    );

    let input_queue_num = input.parse::<u16>()?;
    let output_queue_num = output.parse::<u16>()?;
    let ruleset = std::fs::read_to_string(ruleset)?;
    let rules: Vec<Rule> = serde_json::from_str(&ruleset)?;

    intercept(input_queue_num, output_queue_num, rules)?;

    Ok(())
}
