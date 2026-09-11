// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2023,2024,2025 Bryan Biedenkapp, N2PLL
 *
 */
/**
 * @file RTPFNEHeader.h
 * @ingroup network_core
 * @file RTPFNEHeader.cpp
 * @ingroup network_core
 */
#if !defined(__RTP_FNE_HEADER_H__)
#define __RTP_FNE_HEADER_H__

#include "common/Defines.h"
#include "common/network/RTPExtensionHeader.h"

#include <chrono>
#include <random>
#include <string>

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

#define RTP_FNE_HEADER_LENGTH_BYTES 16
#define RTP_FNE_HEADER_LENGTH_EXT_LEN 4

// Quality-extended form: one additional 32-bit word (Quality Flags | BER | RSSI |
// Quality Protocol) carrying a per-hop signal-quality report. This is used ONLY on
// links that have negotiated it (see the "qualityReporting" RPTC capability flag) -
// every existing caller keeps sending/receiving the unextended 4-word form untouched.
// Not part of the upstream DVMProject protocol; added for a downstream voting
// comparator project ("dvmvoter", https://github.com/connorjfarrell/dvmvoter).
#define RTP_FNE_HEADER_LENGTH_QUALITY_BYTES 20
#define RTP_FNE_HEADER_LENGTH_EXT_QUALITY_LEN 5

#define RTP_END_OF_CALL_SEQ 65535

namespace network
{
    // ---------------------------------------------------------------------------
    //  Constants
    // ---------------------------------------------------------------------------

    /**
     * @brief Network Functions
     * @ingroup network_core
     */
    namespace NET_FUNC {
        enum ENUM : uint8_t {
            ILLEGAL = 0xFFU,                        //!< Illegal Function

            PROTOCOL = 0x00U,                       //!< Digital Protocol Function

            MASTER = 0x01U,                         //!< Network Master Function

            RPTL = 0x60U,                           //!< Repeater Login
            RPTK = 0x61U,                           //!< Repeater Authorisation
            RPTC = 0x62U,                           //!< Repeater Configuration

            RPT_DISC = 0x70U,                       //!< Repeater Disconnect
            MST_DISC = 0x71U,                       //!< Master Disconnect

            PING = 0x74U,                           //!< Ping
            PONG = 0x75U,                           //!< Pong

            GRANT_REQ = 0x7AU,                      //!< Grant Request
            INCALL_CTRL = 0x7BU,                    //!< In-Call Control
            KEY_REQ = 0x7CU,                        //!< Encryption Key Request
            KEY_RSP = 0x7DU,                        //!< Encryption Key Response

            ACK = 0x7EU,                            //!< Packet Acknowledge
            NAK = 0x7FU,                            //!< Packet Negative Acknowledge

            TRANSFER = 0x90U,                       //!< Network Transfer Function

            ANNOUNCE = 0x91U,                       //!< Network Announce Function

            REPL = 0x92U,                           //!< FNE Replication Function
            NET_TREE = 0x93U                        //!< FNE Network Tree Function
        };
    };

    /**
     * @brief Network Sub-Functions
     * @ingroup network_core
     */
    namespace NET_SUBFUNC {
        enum ENUM : uint8_t {
            NOP = 0xFFU,                            //!< No Operation Sub-Function

            PROTOCOL_SUBFUNC_DMR = 0x00U,           //!< DMR
            PROTOCOL_SUBFUNC_P25 = 0x01U,           //!< P25
            PROTOCOL_SUBFUNC_NXDN = 0x02U,          //!< NXDN
            PROTOCOL_SUBFUNC_P25_P2 = 0x03U,        //!< P25 Phase 2
            PROTOCOL_SUBFUNC_ANALOG = 0x0FU,        //!< Analog

            MASTER_SUBFUNC_WL_RID = 0x00U,          //!< Whitelist RIDs
            MASTER_SUBFUNC_BL_RID = 0x01U,          //!< Blacklist RIDs
            MASTER_SUBFUNC_ACTIVE_TGS = 0x02U,      //!< Active TGIDs
            MASTER_SUBFUNC_DEACTIVE_TGS = 0x03U,    //!< Deactive TGIDs
            MASTER_HA_PARAMS = 0xA3U,               //!< HA Parameters

            TRANSFER_SUBFUNC_ACTIVITY = 0x01U,      //!< Activity Log Transfer
            TRANSFER_SUBFUNC_DIAG = 0x02U,          //!< Diagnostic Log Transfer
            TRANSFER_SUBFUNC_STATUS = 0x03U,        //!< Status Transfer

            ANNC_SUBFUNC_GRP_AFFIL = 0x00U,         //!< Announce Group Affiliation
            ANNC_SUBFUNC_UNIT_REG = 0x01U,          //!< Announce Unit Registration
            ANNC_SUBFUNC_UNIT_DEREG = 0x02U,        //!< Announce Unit Deregistration
            ANNC_SUBFUNC_GRP_UNAFFIL = 0x03U,       //!< Announce Group Affiliation Removal
            ANNC_SUBFUNC_AFFILS = 0x90U,            //!< Update All Affiliations
            ANNC_SUBFUNC_SITE_VC = 0x9AU,           //!< Announce Site VCs

            REPL_TALKGROUP_LIST = 0x00U,            //!< FNE Replication Talkgroup Transfer
            REPL_RID_LIST = 0x01U,                  //!< FNE Replication Radio ID Transfer
            REPL_PEER_LIST = 0x02U,                 //!< FNE Replication Peer List Transfer

            REPL_ACT_PEER_LIST = 0xA2U,             //!< FNE Replication Active Peer List Transfer
            REPL_HA_PARAMS = 0xA3U,                 //!< FNE Replication HA Parameters

            NET_TREE_LIST = 0x00U,                  //!< FNE Network Tree List
            NET_TREE_DISC = 0x01U                   //!< FNE Network Tree Disconnect
        };
    };

    /**
     * @brief Network In-Call Control
     * @ingroup network_core
     */
    namespace NET_ICC {
        enum ENUM : uint8_t {
            NOP = 0xFFU,                            //!< No Operation Sub-Function

            BUSY_DENY = 0x00U,                      //!< Busy Deny
            REJECT_TRAFFIC = 0x01U,                 //!< Reject Active Traffic
        };
    };

    /**
     * @brief Quality-extended RTPFNEHeader flag bits (byte 0 of the quality word).
     *  Explicit validity bits, not sentinel values, so "never arrived" is unambiguous
     *  from "arrived and reported clean". See RTPFNEHeader::getQualityPresent().
     * @ingroup network_core
     */
    namespace QUALITY_FLAG {
        enum ENUM : uint8_t {
            NONE = 0x00U,                           //!< No quality flags set

            RSSI_VALID = 0x01U,                     //!< bit0 - RSSI byte is valid
            BER_VALID = 0x02U,                      //!< bit1 - BER byte is valid
            // remaining bits reserved
        };
    };

    /**
     * @brief Quality-extended RTPFNEHeader protocol byte (byte 3 of the quality word).
     *  Reserves room for a future non-P25 voting extension without another wire-format
     *  break; only P25 is defined today.
     * @ingroup network_core
     */
    namespace QUALITY_PROTOCOL {
        enum ENUM : uint8_t {
            P25 = 0x00U,                            //!< P25 (only defined value today)
            // DMR/analog values intentionally undefined - do not assign one without
            // coordinating with the downstream project that consumes this extension
        };
    };

    namespace frame
    {
        // ---------------------------------------------------------------------------
        //  Constants
        // ---------------------------------------------------------------------------

        const uint8_t DVM_FRAME_START = 0xFEU;

        // ---------------------------------------------------------------------------
        //  Class Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief Represents the FNE RTP Extension header.
         * \code{.unparsed}
         * Byte 0               1               2               3
         * Bit  7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Encoded RTP Extension Header                                  |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Payload CRC-16                | Function      | Sub-function  |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Stream ID                                                     |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Peer ID                                                       |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Message Length                                                |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     | Quality Flags | BER (0-255)   | RSSI (0-255)  | Quality Proto.| (quality-extended form only)
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 20 bytes (16 bytes without RTP Extension Header), or 24/20 bytes for the
         * quality-extended form (getQualityPresent() == true)
         * \endcode
         *
         * The quality word is an opt-in extension: decode() accepts both the standard
         * 4-word payload and the 5-word quality-extended payload (discriminated by
         * payloadLength, exactly like every other length-versioned decode in this class),
         * and encode() only emits the 5th word when setQualityPresent(true) has been
         * called - every existing caller that never touches the quality fields continues
         * to produce byte-identical 4-word output. Not part of the upstream DVMProject
         * protocol; added for a downstream voting comparator project ("dvmvoter",
         * https://github.com/connorjfarrell/dvmvoter) - see that project's
         * docs/UPSTREAM.md for the full rationale.
         */
        class HOST_SW_API RTPFNEHeader : public RTPExtensionHeader {
        public:
            /**
             * @brief Initializes a new instance of the RTPFNEHeader class.
             */
            RTPFNEHeader();
            /**
             * @brief Finalizes a instance of the RTPFNEHeader class.
             */
            ~RTPFNEHeader();

            /**
             * @brief Decode a RTP header.
             * @param[in] data Buffer containing RTP FNE header to decode.
             */
            bool decode(const uint8_t* data) override;
            /**
             * @brief Encode a RTP header.
             * @param[out] data Buffer to encode an RTP FNE header.
             */
            void encode(uint8_t* data) override;

            /**
             * @brief Total encoded length of this header in bytes (RTP extension header +
             *  FNE body), derived from payloadLength - callers should use this instead of
             *  assuming a fixed size, since it varies with getQualityPresent().
             */
            uint32_t size() const;

        public:
            /**
             * @brief Traffic payload packet CRC-16.
             */
            DECLARE_PROPERTY(uint16_t, crc16, CRC);
            /**
             * @brief Function.
             */
            DECLARE_PROPERTY(NET_FUNC::ENUM, func, Function);
            /**
             * @brief Sub-function.
             */
            DECLARE_PROPERTY(NET_SUBFUNC::ENUM, subFunc, SubFunction);
            /**
             * @brief Traffic Stream ID.
             */
            DECLARE_PROPERTY(uint32_t, streamId, StreamId);
            /**
             * @brief Traffic Peer ID.
             */
            DECLARE_PROPERTY(uint32_t, peerId, PeerId);
            /**
             * @brief Traffic Message Length.
             */
            DECLARE_PROPERTY(uint32_t, messageLength, MessageLength);

            /**
             * @brief Flag indicating whether the quality-extended (5-word) form is used.
             *  Setting this true is what makes encode() emit the quality word; decode()
             *  sets it based on the payloadLength actually received. See the class remarks
             *  above - this is a downstream ("dvmvoter") extension, opt-in per link.
             */
            DECLARE_PROPERTY(bool, qualityPresent, QualityPresent);
            /**
             * @brief Quality Flags bitfield (see the QUALITY_FLAG namespace) - which of
             *  BER/RSSI below are actually valid. Only meaningful when getQualityPresent().
             */
            DECLARE_PROPERTY(uint8_t, qualityFlags, QualityFlags);
            /**
             * @brief Bit error rate, 0-255 scale, lower is better, valid only if
             *  QUALITY_FLAG::BER_VALID is set in qualityFlags.
             */
            DECLARE_PROPERTY(uint8_t, ber, BER);
            /**
             * @brief Received signal strength, 0-255 magnitude (DFSI-style representation),
             *  lower is better, valid only if QUALITY_FLAG::RSSI_VALID is set in qualityFlags.
             */
            DECLARE_PROPERTY(uint8_t, rssi, RSSI);
            /**
             * @brief Quality protocol/mode (see the QUALITY_PROTOCOL namespace).
             */
            DECLARE_PROPERTY(uint8_t, qualityProtocol, QualityProtocol);
        };
    } // namespace frame
} // namespace network

#endif // __RTP_FNE_HEADER_H__