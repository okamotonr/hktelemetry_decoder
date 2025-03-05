use std::{char, fmt};

use crate::def::{
    application_id, ccsds_v, get_time, has_secondary_header, packet_type, seq_count, seq_flags, CCSDSPrimaryHeader, CCSDSSpacePacket, CCSDSVersion, CFEMSGMessage, CFEMSGTelemetryHeader, CFEMSGTelemetrySecondaryHeader, DSHKPacket, DSHKTlmPayload, PacketType
};

impl fmt::Display for DSHKTlmPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filename: String = self
            .filter_tbl_filename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        writeln!(f, "cmd_accepted_counter: {}", self.cmd_accepted_counter)?;
        writeln!(f, "cmd_rejected_counter: {}", self.cmd_rejected_counter)?;
        writeln!(f, "dest_tbl_load_counter: {}", self.dest_tbl_load_counter)?;
        writeln!(f, "dest_tbl_err_counter: {}", self.dest_tbl_err_counter)?;
        writeln!(
            f,
            "filter_tbl_load_counter: {}",
            self.filter_tbl_load_counter
        )?;
        writeln!(f, "filter_tbl_err_counter: {}", self.filter_tbl_err_counter)?;
        writeln!(f, "app_enable_state: {}", self.app_enable_state)?;
        writeln!(f, "spare8: {}", self.spare8)?;
        writeln!(f, "file_write_counter: {}", self.file_write_counter)?;
        writeln!(f, "file_write_err_counter: {}", self.file_write_err_counter)?;
        writeln!(f, "file_update_counter: {}", self.file_update_counter)?;
        writeln!(
            f,
            "file_update_err_counter: {}",
            self.file_update_err_counter
        )?;
        writeln!(f, "disabled_pkt_counter: {}", self.disabled_pkt_counter)?;
        writeln!(f, "ignored_pkt_counter: {}", self.ignored_pkt_counter)?;
        writeln!(f, "filtered_pkt_counter: {}", self.filtered_pkt_counter)?;
        writeln!(f, "passed_pkt_counter: {}", self.passed_pkt_counter)?;
        write!(f, "filter_tbl_filename: {}", filename)
    }
}

impl fmt::Display for DSHKPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "telemetry_header:")?;
        writeln!(f, "{}", self.telemetry_header)?;
        writeln!(f, "payload:")?;
        write!(f, "{}", self.payload)
    }
}

impl fmt::Display for CFEMSGTelemetryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "primary header:")?;
        write!(f, "{}", self.msg)?;
        if self.msg.has_secondary_header() {
            writeln!(f, "secondary header:")?;
            write!(f, "{}", self.sec)
        } else {
            writeln!(f, "no secondary header")
        }
    }
}

impl fmt::Display for CFEMSGMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ccsds)
    }
}

impl fmt::Display for CCSDSSpacePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pri)
    }
}

impl fmt::Display for CCSDSPrimaryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stream_id = self.get_stream_id();
        writeln!(f, "stream_id: {}", stream_id)?;

        let app_id = application_id(stream_id);
        writeln!(f, "application_id: {}", app_id)?;

        let has_sec_header = has_secondary_header(stream_id);
        writeln!(f, "has_secondary_header: {}", has_sec_header)?;

        let p_type = packet_type(stream_id);
        write!(f, "packet_type: {}", p_type)?;
        let version = ccsds_v(stream_id);
        write!(f, "ccsds_v: {}", version)?;

        let seq = self.get_seq();
        writeln!(f, "sequence: {}", seq)?;
        let seq_count = seq_count(seq);
        writeln!(f, "sequence count: {}", seq_count)?;
        let seq_flags = seq_flags(seq);
        writeln!(f, "sequence flags: {}", seq_flags)?;

        let length = self.get_length();
        writeln!(f, "length: {}", length)
    }
}

impl fmt::Display for CFEMSGTelemetrySecondaryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (seconds, subseconds) = self.get_seconds_and_subseconds();
        writeln!(f, "seconds: {}", seconds)?;
        writeln!(f, "subseconds: {}", subseconds)?;
        let time = get_time(seconds, subseconds);
        write!(f, "time: {}", time)
    }
}

impl fmt::Display for CCSDSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CCSDSVersion::Ver1 => {
                writeln!(f, "version 1")
            },
            CCSDSVersion::Ver2 => {
                writeln!(f, "version 2")
            }
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::TLM => writeln!(f, "telemetry"),
            PacketType::CMD => writeln!(f, "command")
        }
    }
}
