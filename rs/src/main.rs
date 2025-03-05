use std::fs;
use std::env;
use parser::parse_dshk_packet;

mod def;
mod parser;
mod fmt;


fn main() {
    // TODO: use clap
    let file_path = env::args().nth(1).expect("file path");
    let ds_tlm: Vec<u8> = fs::read(file_path).expect("cannot open ds_tlm");
    let mut data: &[u8] = &ds_tlm;
    loop {
        let (_data, dshk_packet) = parse_dshk_packet(data).expect("parser failed");
        println!("{dshk_packet}");
        data = _data;
        if data.len() == 0 {
            break;
        }
        println!();
    }
}
