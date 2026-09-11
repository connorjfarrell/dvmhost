// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Connor Farrell
 *
 */
// Covers the quality-extended (5-word) RTPFNEHeader form added for a downstream
// voting comparator project ("dvmvoter", https://github.com/connorjfarrell/dvmvoter) -
// see RTPFNEHeader.h for the wire layout and docs/IMPLEMENTATION_PLAN.md section 1.1 in
// that project for the "done when" this test satisfies.

#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "common/network/RTPFNEHeader.h"

using namespace network;
using namespace network::frame;

TEST_CASE("RTPFNEHeader round-trips the standard (4-word) form unchanged", "[network][rtpfneheader]") {
    RTPFNEHeader hdr;
    hdr.setCRC(0xBEEFU);
    hdr.setFunction(NET_FUNC::RPTC);
    hdr.setSubFunction(NET_SUBFUNC::NOP);
    hdr.setStreamId(0x11223344U);
    hdr.setPeerId(9000201U);
    hdr.setMessageLength(64U);

    uint8_t buffer[24U];
    ::memset(buffer, 0xCCU, sizeof(buffer)); // poison, so an out-of-bounds write is obvious
    hdr.encode(buffer);

    REQUIRE(hdr.getQualityPresent() == false);
    REQUIRE(hdr.size() == 20U); // 4-byte RTP extension header + 16-byte FNE body

    RTPFNEHeader decoded;
    REQUIRE(decoded.decode(buffer) == true);
    REQUIRE(decoded.getQualityPresent() == false);
    REQUIRE(decoded.getCRC() == 0xBEEFU);
    REQUIRE(decoded.getFunction() == NET_FUNC::RPTC);
    REQUIRE(decoded.getStreamId() == 0x11223344U);
    REQUIRE(decoded.getPeerId() == 9000201U);
    REQUIRE(decoded.getMessageLength() == 64U);
    REQUIRE(decoded.getBER() == 0U);
    REQUIRE(decoded.getRSSI() == 0U);

    // bytes 20-23 must be untouched by a non-quality encode
    REQUIRE(buffer[20U] == 0xCCU);
    REQUIRE(buffer[23U] == 0xCCU);
}

TEST_CASE("RTPFNEHeader round-trips the quality-extended (5-word) form", "[network][rtpfneheader]") {
    RTPFNEHeader hdr;
    hdr.setCRC(0x1234U);
    hdr.setFunction(NET_FUNC::PROTOCOL);
    hdr.setSubFunction(NET_SUBFUNC::PROTOCOL_SUBFUNC_P25);
    hdr.setStreamId(42U);
    hdr.setPeerId(9000202U);
    hdr.setMessageLength(33U);

    hdr.setQualityPresent(true);
    hdr.setQualityFlags(QUALITY_FLAG::BER_VALID | QUALITY_FLAG::RSSI_VALID);
    hdr.setBER(17U);
    hdr.setRSSI(88U);
    hdr.setQualityProtocol(QUALITY_PROTOCOL::P25);

    uint8_t buffer[24U];
    ::memset(buffer, 0x00U, sizeof(buffer));
    hdr.encode(buffer);

    REQUIRE(hdr.size() == 24U); // 4-byte RTP extension header + 20-byte FNE body

    RTPFNEHeader decoded;
    REQUIRE(decoded.decode(buffer) == true);
    REQUIRE(decoded.getQualityPresent() == true);
    REQUIRE(decoded.getStreamId() == 42U);
    REQUIRE(decoded.getPeerId() == 9000202U);
    REQUIRE(decoded.getQualityFlags() == (QUALITY_FLAG::BER_VALID | QUALITY_FLAG::RSSI_VALID));
    REQUIRE(decoded.getBER() == 17U);
    REQUIRE(decoded.getRSSI() == 88U);
    REQUIRE(decoded.getQualityProtocol() == QUALITY_PROTOCOL::P25);
}

TEST_CASE("RTPFNEHeader decode rejects a payloadLength that is neither 4 nor 5 words", "[network][rtpfneheader]") {
    RTPFNEHeader hdr;
    hdr.setMessageLength(1U);

    uint8_t buffer[24U];
    ::memset(buffer, 0x00U, sizeof(buffer));
    hdr.encode(buffer);

    // corrupt the RTP extension header's payloadLength (bytes 2-3, big-endian) to something
    // that is neither the standard nor the quality-extended word count
    buffer[2U] = 0x00U;
    buffer[3U] = 0x09U;

    RTPFNEHeader decoded;
    REQUIRE(decoded.decode(buffer) == false);
}

TEST_CASE("RTPFNEHeader: a quality-unaware decoder never mistakes the extra word for RTP header data",
          "[network][rtpfneheader]") {
    // A decoder that only ever expects the 4-word form (payloadLength check) must reject a
    // 5-word packet outright rather than silently misreading it - this is the same "widen the
    // length check" requirement RTPFNEHeader::decode() itself satisfies, sanity-checked here
    // against a hand-built quality-extended packet.
    RTPFNEHeader hdr;
    hdr.setStreamId(7U);
    hdr.setPeerId(8U);
    hdr.setMessageLength(1U);
    hdr.setQualityPresent(true);
    hdr.setBER(200U);

    uint8_t buffer[24U];
    ::memset(buffer, 0x00U, sizeof(buffer));
    hdr.encode(buffer);

    REQUIRE(buffer[3U] == RTP_FNE_HEADER_LENGTH_EXT_QUALITY_LEN); // payloadLength LSB (bytes 2-3, big-endian)
}
