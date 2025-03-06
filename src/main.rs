mod utils;

use utils::zk::extract_pvk;
use clap::{Arg, Command};


#[tokio::main]
async fn main() {
    //read args
    let matches = Command::new("extract_pvk")
        .version("0.1")
        .author("David Dantas")
        .about("Extracts the prepared verifying key from a .arkzkey file")
        .arg(Arg::new("input")
            .short('i')
            .long("input")
            .value_name("INPUT")
            .help("Sets the input file to use")
            .required(true)
            .action(clap::ArgAction::Set))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("OUTPUT")
            .help("Sets the output file to use")
            .required(true)
            .action(clap::ArgAction::Set))
        .get_matches();

    let input = matches.get_one::<String>("input").unwrap();
    let output = matches.get_one::<String>("output").unwrap();

    extract_pvk(&input.to_string(), &output.to_string());
}