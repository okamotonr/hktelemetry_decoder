pub const OS_MAX_PATH_LEN: usize = 32;
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::os::raw::c_char;

// https://github.com/nasa/DS/blob/7404b975be4b4a2e2a51eab4c1fa6a9b7a8630c4/fsw/inc/ds_msg.h
// https://github.com/nasa/cFE/blob/4b3fedd971d704ce4782f62ad92f9f0a56ff8eaa/modules/msg/option_inc/default_cfe_msg_hdr_pri.h
// https://github.com/nasa/cFE/blob/4b3fedd971d704ce4782f62ad92f9f0a56ff8eaa/modules/msg/option_inc/default_cfe_msg_sechdr.h
// https://github.com/nasa/cFE/blob/4b3fedd971d704ce4782f62ad92f9f0a56ff8eaa/modules/msg/fsw/inc/ccsds_hdr.h

#[derive(Debug)]
pub struct DSHKTlmPayload {
    /// Count of valid command recieve
    pub cmd_accepted_counter: u8,
    /// Count of invalid commands received
    pub cmd_rejected_counter: u8,
    /// Count of destination file table loads
    pub dest_tbl_load_counter: u8,
    /// Count of failed attempts to get table data pointer
    pub dest_tbl_err_counter: u8,
    /// Count of packet filter table loads
    pub filter_tbl_load_counter: u8,
    /// Count of failed attempts to get table data pointer
    pub filter_tbl_err_counter: u8,
    /// Application enable/disable state
    pub app_enable_state: u8,
    /// Structure alignment padding
    pub spare8: u8,
    /// Count of good destination file writes */
    pub file_write_counter: u16,
    /// Count of bad destination file writes
    pub file_write_err_counter: u16,
    /// Count of good updates to secondary header
    pub file_update_counter: u16,
    /// Count of bad updates to secondary header
    pub file_update_err_counter: u16,
    /// Count of packets discarded (DS was disabled)
    pub disabled_pkt_counter: u32,
    /// Count of packets discarded
    /// Incoming packets will be discarded when:
    ///  - The File and/or Filter Table has failed to load
    ///  - A packet (that is not a DS HK or command packet) has been received
    ///    that is not listed in the Filter Table
    pub ignored_pkt_counter: u32,
    /// Count of packets discarded (failed filter test)
    pub filtered_pkt_counter: u32,
    /// Count of packets that passed filter test
    pub passed_pkt_counter: u32,
    /// Name of filter table file
    pub filter_tbl_filename: [c_char; OS_MAX_PATH_LEN],
}

#[derive(Debug)]
pub struct DSHKPacket {
    pub telemetry_header: CFEMSGTelemetryHeader,
    pub payload: DSHKTlmPayload,
}

impl DSHKPacket {}

#[derive(Debug)]
pub struct CFEMSGTelemetryHeader {
    /// Base message
    pub msg: CFEMSGMessage,
    /// Secondary header
    pub sec: CFEMSGTelemetrySecondaryHeader,
    // https://github.com/nasa/cFS/discussions/720
    // Pad to avoid compiler padding if payload requires 64 bit alignment
    //pub spare: [u8; 4],
}

#[derive(Debug)]
pub struct CFEMSGMessage {
    /// CCSDS Header (Pri or Pri + Ext)
    pub ccsds: CCSDSSpacePacket,
}

impl CFEMSGMessage {
    pub fn has_secondary_header(&self) -> bool {
        self.ccsds.pri.has_secondary_header()
    }
}

#[derive(Debug)]
pub struct CCSDSSpacePacket {
    /// CCSDS Primary Header
    pub pri: CCSDSPrimaryHeader,
}

#[derive(Debug)]
pub struct CFEMSGTelemetrySecondaryHeader {
    /// Time, big endian: 4 byte seconds, 2 byte subseconds
    pub time: [u8; 6],
}

impl CFEMSGTelemetrySecondaryHeader {
    pub fn get_seconds_and_subseconds(&self) -> (u32, u16) {
        let seconds = (self.time[0] as u32) << 24
            | (self.time[1] as u32) << 16
            | (self.time[2] as u32) << 8
            | (self.time[3] as u32);
        let subseconds = (self.time[4] as u16) << 8 | (self.time[5] as u16);
        (seconds, subseconds)
    }
}

const BASE_YEAR: i32 = 2000;
const BASE_MONTH: u32 = 1;
const BASE_DAY: u32 = 1;
const BASE_HOUR: u32 = 11;
const BASE_MINUTE: u32 = 58;
const BASE_SECONDS: u32 = 55;
const BASE_MILISEC: Duration = Duration::milliseconds(816);

pub fn get_time(seconds: u32, subseconds: u16) -> DateTime<Utc> {
    let base_time = Utc
        .with_ymd_and_hms(
            BASE_YEAR,
            BASE_MONTH,
            BASE_DAY,
            BASE_HOUR,
            BASE_MINUTE,
            BASE_SECONDS,
        )
        .unwrap();
    let base_time = base_time + BASE_MILISEC;
    let added_duration =
        Duration::seconds(seconds as i64) + Duration::milliseconds(subseconds as i64);
    base_time + added_duration
}

#[derive(Debug)]
pub struct CCSDSPrimaryHeader {
    /// packet identifier word (stream ID)
    /// bits  shift   ------------ description ----------------
    /// 0x07FF    0  : application ID                            
    /// 0x0800   11  : secondary header: 0 = absent, 1 = present
    /// 0x1000   12  : packet type:      0 = TLM, 1 = CMD        
    /// 0xE000   13  : CCSDS version:    0 = ver 1, 1 = ver 2    
    pub stream_id: [u8; 2],
    /// packet sequence word
    ///  bits  shift   ------------ description ----------------
    /// 0x3FFF    0  : sequence count                            
    /// 0xC000   14  : segmentation flags:  3 = complete packet  
    pub sequence: [u8; 2],
    /// packet length word
    ///  bits  shift   ------------ description ----------------
    /// 0xFFFF    0  : (total packet length) - 7                 
    pub length: [u8; 2],
}

pub fn application_id(stream_id: u16) -> u16 {
    stream_id & 0x07FF
}

pub fn has_secondary_header(stream_id: u16) -> bool {
    ((stream_id & 0x0800) >> 11) == 1
}

pub fn ccsds_v(stream_id: u16) -> CCSDSVersion {
    let ccsds_v_num = (stream_id & 0xE000) >> 13;
    if ccsds_v_num == 0 {
        CCSDSVersion::Ver1
    } else if ccsds_v_num == 1 {
        CCSDSVersion::Ver2
    } else {
        panic!("Unknown version")
    }
}

pub fn packet_type(stream_id: u16) -> PacketType {
    let packet_type_num = (stream_id & 0x1000) >> 12;
    if packet_type_num == 1 {
        PacketType::CMD
    } else if packet_type_num == 0 {
        PacketType::TLM
    } else {
        panic!("Unknown type")
    }
}

pub fn seq_count(sequence: u16) -> u16 {
    sequence & 0x3FFF
}

pub fn seq_flags(sequence: u16) -> u16 {
    (sequence & 0xC000) >> 14
}

impl CCSDSPrimaryHeader {
    pub fn get_stream_id(&self) -> u16 {
        (self.stream_id[0] as u16) << 8 | self.stream_id[1] as u16
    }

    pub fn get_seq(&self) -> u16 {
        (self.sequence[0] as u16) << 8 | self.sequence[1] as u16
    }

    pub fn get_length(&self) -> u16 {
        (self.length[0] as u16) << 8 | self.length[1] as u16
    }

    fn has_secondary_header(&self) -> bool {
        let stream_id = self.get_stream_id();
        has_secondary_header(stream_id)
    }
}

#[derive(Debug)]
pub enum CCSDSVersion {
    Ver1,
    Ver2,
}

#[derive(Debug)]
pub enum PacketType {
    TLM,
    CMD,
}
