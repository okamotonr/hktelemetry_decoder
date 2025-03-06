use std::fs;
use std::env;
use parser::parse_dshk_packet;

mod def;
mod parser;
mod disp;

fn main() {
    // TODO: use clap
    let file_path = env::args().nth(1).expect("file path required");
    let ds_tlm: Vec<u8> = fs::read(file_path).expect("cannot read ds_tlm");

    let mut data: &[u8] = &ds_tlm;
    while !data.is_empty() {
        let (remaining, dshk_packet) = parse_dshk_packet(data).expect("parser failed");
        println!("{dshk_packet}");
        data = remaining;
        println!();
    }
}
