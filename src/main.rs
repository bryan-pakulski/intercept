pub mod error;
pub mod net;
pub mod rules;

use clap::{Arg, Command};

use error::BackendError;
use net::listen;
use rules::Rule;

fn usage() {
    println!(
        "Usage: intercept -i <interface> -p <port> -r <ruleset>\n\n\
        Options:\n  \
        -i, --interface    Specify the network interface\n  \
        -p, --port         Specify the port to bind\n  \
        -r, --ruleset      Path to the ruleset JSON file"
    );
}

fn main() -> Result<(), BackendError> {
    env_logger::init();

    let matches = Command::new("intercept")
        .version("1.0")
        .about("SIP packet interceptor for header manipulation")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .required(true)
                .help("Specify the network interface")
                .value_name("INTERFACE"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .required(true)
                .help("Specify the port to bind")
                .value_name("PORT"),
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

    let interface = matches
        .get_one::<String>("interface")
        .expect("interface is required");
    let port = matches.get_one::<String>("port").expect("port is required");
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

    println!("{}", art);
    println!(
        "iface: {}   ==   port: {}   ==   ruleset: {}",
        interface, port, ruleset
    );

    let port = port.parse::<u16>()?;
    let ruleset = std::fs::read_to_string(ruleset)?;
    let rules: Vec<Rule> = serde_json::from_str(&ruleset)?;
    listen(interface, port, &rules);

    Ok(())
}
