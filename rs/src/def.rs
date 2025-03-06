pub const OS_MAX_PATH_LEN: usize = 32;
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::os::raw::c_char;

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
    #[allow(dead_code)]
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
        self.ccsds.pri.has_secondary_header
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
    /// pub time: [u8; 6],
    pub seconds: u32,
    pub subseconds: u16
}

impl CFEMSGTelemetrySecondaryHeader {
    pub fn as_date(&self) -> DateTime<Utc> {
        let base_time = Utc
            .with_ymd_and_hms(
                BASE_YEAR,
                BASE_MONTH,
                BASE_DAY,
                BASE_HOUR,
                BASE_MINUTE,
                BASE_SECONDS,
            ).unwrap();
    let base_time = base_time + BASE_MILISEC;
    let duration = Duration::seconds(self.seconds as i64) +
        Duration::milliseconds(self.subseconds as i64);
    let ret = base_time + duration;
    ret
    }

}


const BASE_YEAR: i32 = 2000;
const BASE_MONTH: u32 = 1;
const BASE_DAY: u32 = 1;
const BASE_HOUR: u32 = 11;
const BASE_MINUTE: u32 = 58;
const BASE_SECONDS: u32 = 55;
const BASE_MILISEC: Duration = Duration::milliseconds(816);

#[derive(Debug)]
pub struct CCSDSPrimaryHeader {
    /// packet identifier word (stream ID)
    /// bits  shift   ------------ description ----------------
    /// 0x07FF    0  : application ID                            
    /// 0x0800   11  : secondary header: 0 = absent, 1 = present
    /// 0x1000   12  : packet type:      0 = TLM, 1 = CMD        
    /// 0xE000   13  : CCSDS version:    0 = ver 1, 1 = ver 2    
    pub application_id: u16,
    pub has_secondary_header: bool,
    pub packet_type: PacketType,
    pub ccsds_v: CCSDSVersion,
    /// packet sequence word
    ///  bits  shift   ------------ description ----------------
    /// 0x3FFF    0  : sequence count                            
    /// 0xC000   14  : segmentation flags:  3 = complete packet  
    pub sequence_count: u16,
    pub segmentation_flags: u8,
    /// packet length word
    ///  bits  shift   ------------ description ----------------
    /// 0xFFFF    0  : (total packet length) - 7                 
    pub length: u16,
}

pub fn get_application_id(stream_id: u16) -> u16 {
    stream_id & 0x07FF
}

pub fn get_has_secondary_header(stream_id: u16) -> bool {
    ((stream_id & 0x0800) >> 11) == 1
}

pub fn get_ccsds_v(stream_id: u16) -> CCSDSVersion {
    let ccsds_v_num = (stream_id & 0xE000) >> 13;
    if ccsds_v_num == 0 {
        CCSDSVersion::Ver1
    } else if ccsds_v_num == 1 {
        CCSDSVersion::Ver2
    } else {
        CCSDSVersion::Unknown(ccsds_v_num as u8)
    }
}

pub fn get_packet_type(stream_id: u16) -> PacketType {
    let packet_type_num = (stream_id & 0x1000) >> 12;
    if packet_type_num == 1 {
        PacketType::CMD
    } else if packet_type_num == 0 {
        PacketType::TLM
    } else {
        unreachable!("unreachable!")
    }
}

pub fn get_seq_count(sequence: u16) -> u16 {
    sequence & 0x3FFF
}

pub fn get_seg_flags(sequence: u16) -> u8 {
    ((sequence & 0xC000) >> 14) as u8
}

#[derive(Debug)]
pub enum CCSDSVersion {
    Ver1,
    Ver2,
    Unknown(u8)
}

#[derive(Debug)]
pub enum PacketType {
    TLM,
    CMD,
}
