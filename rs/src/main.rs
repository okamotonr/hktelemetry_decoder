use std::fs;

use parser::parse_dshk_packet;

mod def;
mod parser;
mod fmt;

fn main() {
    let ds_tlm: Vec<u8> = fs::read("../asset/ds_tlm.bin").expect("cannot open ds_tlm");
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
