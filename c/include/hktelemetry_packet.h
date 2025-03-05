#ifndef HKTELEMETRY_PACKET_H
#define HKTELEMETRY_PACKET_H

#include <stdint.h>

#define  OS_MAX_PATH_LEN 32
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;


/**
 * \brief cFS telemetry secondary header
 */
typedef struct
{
    uint8 Time[6]; /**< \brief Time, big endian: 4 byte seconds, 2 byte subseconds */
} CFE_MSG_TelemetrySecondaryHeader_t;

/**
 * \brief CCSDS packet primary header
 */
typedef struct CCSDS_PrimaryHeader
{
    uint8 StreamId[2]; /**< \brief packet identifier word (stream ID) */
                       /*  bits  shift   ------------ description ---------------- */
                       /* 0x07FF    0  : application ID                            */
                       /* 0x0800   11  : secondary header: 0 = absent, 1 = present */
                       /* 0x1000   12  : packet type:      0 = TLM, 1 = CMD        */
                       /* 0xE000   13  : CCSDS version:    0 = ver 1, 1 = ver 2    */

    uint8 Sequence[2]; /**< \brief packet sequence word */
                       /*  bits  shift   ------------ description ---------------- */
                       /* 0x3FFF    0  : sequence count                            */
                       /* 0xC000   14  : segmentation flags:  3 = complete packet  */

    uint8 Length[2]; /**< \brief packet length word */
                     /*  bits  shift   ------------ description ---------------- */
                     /* 0xFFFF    0  : (total packet length) - 7                 */
} CCSDS_PrimaryHeader_t;

/**
 * \brief Full CCSDS header
 */
typedef struct
{
    CCSDS_PrimaryHeader_t Pri; /**< \brief CCSDS Primary Header */
} CCSDS_SpacePacket_t;

/**
 * \brief cFS generic base message
 *
 * This provides the definition of CFE_MSG_Message_t
 */
typedef struct
{
    CCSDS_SpacePacket_t CCSDS; /**< \brief CCSDS Header (Pri or Pri + Ext) */
} CFE_MSG_Message_t;

/**
 * \brief cFS telemetry header
 *
 * This provides the definition of CFE_MSG_TelemetryHeader_t
 */
typedef struct
{
    CFE_MSG_Message_t                  Msg;      /**< \brief Base message */
    CFE_MSG_TelemetrySecondaryHeader_t Sec;      /**< \brief Secondary header */
} CFE_MSG_TelemetryHeader_t;


/**
 * \defgroup cfsdstlm CFS Data Storage Telemetry
 * \{
 */

typedef struct
{
    uint8  CmdAcceptedCounter;                 /**< \brief Count of valid commands re;ceived */
    uint8  CmdRejectedCounter;                 /**< \brief Count of invalid commands received */
    uint8  DestTblLoadCounter;                 /**< \brief Count of destination file table loads */
    uint8  DestTblErrCounter;                  /**< \brief Count of failed attempts to get table data pointer */
    uint8  FilterTblLoadCounter;               /**< \brief Count of packet filter table loads */
    uint8  FilterTblErrCounter;                /**< \brief Count of failed attempts to get table data pointer */
    uint8  AppEnableState;                     /**< \brief Application enable/disable state */
    uint8  Spare8;                             /**< \brief Structure alignment padding */
    uint16 FileWriteCounter;                   /**< \brief Count of good destination file writes */
    uint16 FileWriteErrCounter;                /**< \brief Count of bad destination file writes */
    uint16 FileUpdateCounter;                  /**< \brief Count of good updates to secondary header */
    uint16 FileUpdateErrCounter;               /**< \brief Count of bad updates to secondary header */
    uint32 DisabledPktCounter;                 /**< \brief Count of packets discarded (DS was disabled) */
    uint32 IgnoredPktCounter;                  /**< \brief Count of packets discarded
                                                *
                                                * Incoming packets will be discarded when:
                                                *  - The File and/or Filter Table has failed to load
                                                *  - A packet (that is not a DS HK or command packet) has been received
                                                *    that is not listed in the Filter Table
                                                */
    uint32 FilteredPktCounter;                 /**< \brief Count of packets discarded (failed filter test) */
    uint32 PassedPktCounter;                   /**< \brief Count of packets that passed filter test */
    char   FilterTblFilename[OS_MAX_PATH_LEN]; /**< \brief Name of filter table file */
} DS_HkTlm_Payload_t;

/**
 * \brief Application housekeeping packet
 */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader; /**< \brief cFE Software Bus telemetry message header */

    DS_HkTlm_Payload_t Payload;
} DS_HkPacket_t;

#endif
