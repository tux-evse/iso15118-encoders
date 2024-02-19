/*
 * Copyright (C) 2015-2022 IoT.bzh Pionix, Chargebyte and Everest contributors
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Rust largely inspired from Everest C++ git@github.com:/EVerest/libiso15118.git
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */
#include "sdp-v2g-encoders.h"
#include <arpa/inet.h>

int sdp_v2g_decode_rqt (const uint8_t* buffer, size_t count, sdp_request *request ) {
    if (count < SDP_V2G_REQUEST_LEN+ SDP_V2G_HEADER_LEN) return -1;

    request->header.version_std= buffer[0];
    request->header.version_not= buffer[1];
    request->header.msg_type= (buffer[2] << 8) | buffer[3];
    request->header.msg_len=(buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];
    request->security= buffer[8];
    request->transport= buffer[9];
    return 0;
}

int sdp_v2g_encode_rsp (const sdp_response* response, uint8_t* buffer, size_t count) {
    if (count < SDP_V2G_RESPONSE_LEN+SDP_V2G_HEADER_LEN) return -1;

    buffer[0] = response->header.version_std;
    buffer[1] = response->header.version_not;

    /* write payload type */
    buffer[2] = (uint8_t)(response->header.msg_type >> 8 & 0xFFu);
    buffer[3] = (uint8_t)(response->header.msg_type & 0xFFu);

    /* write payload length */
    buffer[4] = (uint8_t)(response->header.msg_len >> 24 & 0xFFu);
    buffer[5] = (uint8_t)(response->header.msg_len >> 16 & 0xFFu);
    buffer[6] = (uint8_t)(response->header.msg_len >>  8 & 0xFFu);
    buffer[7] = (uint8_t)(response->header.msg_len & 0xFFu);

    for (int idx=0; idx < sizeof(response->addr.__in6_u.__u6_addr8); idx++) {
       buffer[8+idx] = response->addr.__in6_u.__u6_addr8[idx];
    }

    buffer[24] = (uint8_t)(response->port >> 8 & 0xFFu);
    buffer[25] = (uint8_t)(response->port & 0xFFu);

    buffer[26] = (uint8_t)(response->security);
    buffer[27] = (uint8_t)(response->transport);

    return 0;
}