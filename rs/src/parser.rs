use std::ffi::c_char;

use crate::def::{CCSDSPrimaryHeader, CCSDSSpacePacket, CFEMSGMessage, CFEMSGTelemetryHeader, CFEMSGTelemetrySecondaryHeader, DSHKPacket, DSHKTlmPayload, OS_MAX_PATH_LEN};
use nom::number::complete::{u8, be_u16, be_u32};
use nom::bytes::streaming::take;
use nom::{Err, IResult, Needed};

pub fn parse_dshk_packet(data: &[u8]) -> IResult<&[u8], DSHKPacket> {
    let (data, telemetry_header) = parse_cfe_msg_telemetry_header(data)?;
    let (data, payload) = parse_tlm_payload(data)?;
    let dshk_packet = DSHKPacket {
        telemetry_header,
        payload
    };
    Ok((data, dshk_packet))
}

fn parse_tlm_payload(data: &[u8]) -> IResult<&[u8], DSHKTlmPayload> {
    let (data, cmd_accepted_counter) = u8(data)?;
    let (data, cmd_rejected_counter) = u8(data)?;
    let (data, dest_tbl_load_counter) = u8(data)?;
    let (data, dest_tbl_err_counter) = u8(data)?;
    let (data, filter_tbl_load_counter) = u8(data)?;
    let (data, filter_tbl_err_counter) = u8(data)?;
    let (data, app_enable_state) = u8(data)?;
    let (data, spare8) = u8(data)?;

    let (data, file_write_counter) = be_u16(data)?;
    let (data, file_write_err_counter) = be_u16(data)?;
    let (data, file_update_counter) = be_u16(data)?;
    let (data, file_update_err_counter) = be_u16(data)?;

    let (data, disabled_pkt_counter) = be_u32(data)?;
    let (data, ignored_pkt_counter) = be_u32(data)?;
    let (data, filtered_pkt_counter) = be_u32(data)?;
    let (data, passed_pkt_counter) = be_u32(data)?;

    let (data, filter_tbl_filename) = take(OS_MAX_PATH_LEN)(data)?;

    let filter_tbl_filename: [u8; OS_MAX_PATH_LEN] = filter_tbl_filename.try_into().unwrap();
    let filter_tbl_filename = filter_tbl_filename.map(|b| b as c_char);

    let dshk_tlm_payload = DSHKTlmPayload {
        cmd_accepted_counter,
        cmd_rejected_counter,
        dest_tbl_load_counter,
        dest_tbl_err_counter,
        filter_tbl_load_counter,
        filter_tbl_err_counter,
        app_enable_state,
        spare8,
        file_write_counter,
        file_write_err_counter,
        file_update_counter,
        file_update_err_counter,
        disabled_pkt_counter,
        ignored_pkt_counter,
        filtered_pkt_counter,
        passed_pkt_counter,
        filter_tbl_filename
    };
    Ok((data, dshk_tlm_payload))
}

fn parse_cfe_msg_telemetry_header(data: &[u8]) -> IResult<&[u8], CFEMSGTelemetryHeader> {
    let (data, msg) = parse_cfe_msg_message(data)?;

    let (data, sec) = if msg.has_secondary_header() {
        parse_cfe_msg_telemetry_secondary_header(data)?
    } else {
        (data, CFEMSGTelemetrySecondaryHeader { time: [0; 6] })
    };

    //let (data, spare) = take(4_usize)(data)?;
    //let spare = spare.try_into().unwrap();

    let cfe_t_header = CFEMSGTelemetryHeader {
        msg,
        sec,
        //spare
    };
    Ok((data, cfe_t_header))
}

fn parse_cfe_msg_message(data: &[u8]) -> IResult<&[u8], CFEMSGMessage> {
    let (data, ccsds) = parse_ccsds_space_packet(data)?;
    let cfe_msg = CFEMSGMessage { ccsds };
    Ok((data, cfe_msg))
}

fn parse_ccsds_space_packet(data: &[u8]) -> IResult<&[u8], CCSDSSpacePacket> {
    let (data, pri) = parse_ccsds_primary_header(data)?;
    let length = pri.get_length() as usize;
    (length <= data.len()).then_some(()).ok_or(
        Err::Incomplete(Needed::new(length))
    )?;
    let ccsds_s_packet = CCSDSSpacePacket { pri };
    Ok((data, ccsds_s_packet))
}

fn parse_cfe_msg_telemetry_secondary_header(data: &[u8]) -> IResult<&[u8], CFEMSGTelemetrySecondaryHeader> {
    let (data, time) = take(6_usize)(data)?;
    let time = time.try_into().unwrap();
    let cse_msg_t_s_header = CFEMSGTelemetrySecondaryHeader {time};
    Ok((data, cse_msg_t_s_header))
}

fn parse_ccsds_primary_header(data: &[u8]) -> IResult<&[u8], CCSDSPrimaryHeader> {
    let (data, stream_id) = take(2_usize)(data)?;
    let (data, sequence) = take(2_usize)(data)?;
    let (data, length) = take(2_usize)(data)?;

    let stream_id: [u8; 2] = stream_id.try_into().unwrap();
    let sequence: [u8; 2] = sequence.try_into().unwrap();
    let length: [u8; 2] = length.try_into().unwrap();

    let ccsds_p_header = CCSDSPrimaryHeader {
        stream_id,
        sequence,
        length
    };
    Ok((data, ccsds_p_header))
}
