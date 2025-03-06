use std::{char, ffi::c_char, fmt};

use crate::def::{
    CCSDSPrimaryHeader, CCSDSSpacePacket, CCSDSVersion, CFEMSGMessage, CFEMSGTelemetryHeader,
    CFEMSGTelemetrySecondaryHeader, DSHKPacket, DSHKTlmPayload, PacketType,
};

impl fmt::Display for DSHKTlmPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filename: String = self
            .filter_tbl_filename
            .iter()
            .take_while(|&&c| c != '\0' as c_char)
            .map(|&c| c as u8 as char)
            .collect();
        writeln!(f, "CmdAcceptedCounter: {}", self.cmd_accepted_counter)?;
        writeln!(f, "CmdRejectedCounter: {}", self.cmd_rejected_counter)?;
        writeln!(f, "DestTblLoadCounter: {}", self.dest_tbl_load_counter)?;
        writeln!(f, "DestTblErrCounter: {}", self.dest_tbl_err_counter)?;
        writeln!(
            f,
            "FilterTblLoadCounter: {}",
            self.filter_tbl_load_counter
        )?;
        writeln!(f, "FilterTblErrCounter: {}", self.filter_tbl_err_counter)?;
        writeln!(f, "AppEnableState: {}", self.app_enable_state)?;
        writeln!(f, "FileWriteCounter: {}", self.file_write_counter)?;
        writeln!(f, "FileWriteErrCounter: {}", self.file_write_err_counter)?;
        writeln!(f, "FileUpdateCounter: {}", self.file_update_counter)?;
        writeln!(
            f,
            "FileUpdateErrCounter: {}",
            self.file_update_err_counter
        )?;
        writeln!(f, "DisabledPktCounter: {}", self.disabled_pkt_counter)?;
        writeln!(f, "IgnoredPktCounter: {}", self.ignored_pkt_counter)?;
        writeln!(f, "FilteredPktCounter: {}", self.filtered_pkt_counter)?;
        writeln!(f, "PassedPktCounter: {}", self.passed_pkt_counter)?;
        write!(f, "FilterTblFilename: {}", filename)
    }
}

impl fmt::Display for DSHKPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TelemetryHeader:")?;
        writeln!(f, "{}", self.telemetry_header)?;
        writeln!(f, "Payload:")?;
        write!(f, "{}", self.payload)
    }
}

impl fmt::Display for CFEMSGTelemetryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PrimaryHeader:")?;
        write!(f, "{}", self.msg)?;
        if self.msg.has_secondary_header() {
            writeln!(f, "SecondaryHeader:")?;
            write!(f, "{}", self.sec)
        } else {
            writeln!(f, "No SecondaryHeader")
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
        writeln!(f, "ApplicationID: {}", self.application_id)?;

        writeln!(f, "HasSecondaryHeader: {}", self.has_secondary_header)?;

        write!(f, "PacketType: {}", self.packet_type)?;
        write!(f, "CCSDSVersion: {}", self.ccsds_v)?;

        writeln!(f, "SequenceCount: {}", self.sequence_count)?;
        writeln!(f, "SegmentationFlags: {}", self.segmentation_flags)?;

        writeln!(f, "Length: {}", self.length)
    }
}

impl fmt::Display for CFEMSGTelemetrySecondaryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Seconds: {}", self.seconds)?;
        writeln!(f, "Subseconds: {}", self.subseconds)?;
        let date = self.as_date();
        write!(f, "Date: {}", date)
    }
}

impl fmt::Display for CCSDSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CCSDSVersion::Ver1 => {
                writeln!(f, "Ver1")
            }
            CCSDSVersion::Ver2 => {
                writeln!(f, "Ver2")
            }
            CCSDSVersion::Unknown(val) => {
                writeln!(f, "Unknown {val}")
            }
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::TLM => writeln!(f, "TLM"),
            PacketType::CMD => writeln!(f, "CMD"),
        }
    }
}
