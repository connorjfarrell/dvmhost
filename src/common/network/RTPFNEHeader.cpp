// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2023 Bryan Biedenkapp, N2PLL
 *
 */
#include "Defines.h"
#include "network/RTPFNEHeader.h"
#include "Utils.h"

using namespace network::frame;

#include <cassert>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the RTPFNEHeader class. */

RTPFNEHeader::RTPFNEHeader() :
    RTPExtensionHeader(),
    m_crc16(0U),
    m_func(NET_FUNC::ILLEGAL),
    m_subFunc(NET_SUBFUNC::NOP),
    m_streamId(0U),
    m_peerId(0U),
    m_messageLength(0U),
    m_qualityPresent(false),
    m_qualityFlags(QUALITY_FLAG::NONE),
    m_ber(0U),
    m_rssi(0U),
    m_qualityProtocol(QUALITY_PROTOCOL::P25)
{
    /* stub */
}

/* Finalizes a instance of the RTPFNEHeader class. */

RTPFNEHeader::~RTPFNEHeader() = default;

/* Decode a RTP header. */

bool RTPFNEHeader::decode(const uint8_t* data)
{
    assert(data != nullptr);

    RTPExtensionHeader::decode(data);
    if (m_payloadLength != RTP_FNE_HEADER_LENGTH_EXT_LEN &&
        m_payloadLength != RTP_FNE_HEADER_LENGTH_EXT_QUALITY_LEN) {
        return false;
    }

    if (m_payloadType != DVM_FRAME_START) {
        return false;
    }

    m_crc16 = (data[4U] << 8) | (data[5U] << 0);                                // CRC-16
    m_func = (NET_FUNC::ENUM)data[6U];                                          // Function
    m_subFunc = (NET_SUBFUNC::ENUM)data[7U];                                    // Sub-Function
    m_streamId = GET_UINT32(data, 8U);                                          // Stream ID
    m_peerId = GET_UINT32(data, 12U);                                           // Peer ID
    m_messageLength = GET_UINT32(data, 16U);                                    // Message Length

    // quality-extended (5-word) form - see the class remarks in RTPFNEHeader.h
    m_qualityPresent = (m_payloadLength == RTP_FNE_HEADER_LENGTH_EXT_QUALITY_LEN);
    if (m_qualityPresent) {
        m_qualityFlags = data[20U];                                            // Quality Flags
        m_ber = data[21U];                                                     // BER
        m_rssi = data[22U];                                                    // RSSI
        m_qualityProtocol = data[23U];                                         // Quality Protocol
    } else {
        m_qualityFlags = QUALITY_FLAG::NONE;
        m_ber = 0U;
        m_rssi = 0U;
        m_qualityProtocol = QUALITY_PROTOCOL::P25;
    }

    return true;
}

/* Encode a RTP header. */

void RTPFNEHeader::encode(uint8_t* data)
{
    assert(data != nullptr);

    m_payloadType = DVM_FRAME_START;
    m_payloadLength = m_qualityPresent ? RTP_FNE_HEADER_LENGTH_EXT_QUALITY_LEN : RTP_FNE_HEADER_LENGTH_EXT_LEN;
    RTPExtensionHeader::encode(data);

    data[4U] = (m_crc16 >> 8) & 0xFFU;                                          // CRC-16 MSB
    data[5U] = (m_crc16 >> 0) & 0xFFU;                                          // CRC-16 LSB
    data[6U] = m_func;                                                          // Function
    data[7U] = m_subFunc;                                                       // Sub-Function

    SET_UINT32(m_streamId, data, 8U);                                           // Stream ID
    SET_UINT32(m_peerId, data, 12U);                                            // Peer ID
    SET_UINT32(m_messageLength, data, 16U);                                     // Message Length

    // quality-extended (5-word) form - only emitted when explicitly requested, so every
    // existing caller keeps producing byte-identical 4-word output
    if (m_qualityPresent) {
        data[20U] = m_qualityFlags;                                            // Quality Flags
        data[21U] = m_ber;                                                     // BER
        data[22U] = m_rssi;                                                    // RSSI
        data[23U] = m_qualityProtocol;                                         // Quality Protocol
    }
}

/* Total encoded length of this header in bytes. */

uint32_t RTPFNEHeader::size() const
{
    return RTP_EXTENSION_HEADER_LENGTH_BYTES + (static_cast<uint32_t>(m_payloadLength) * 4U);
}
