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
#include <stdint.h>
#include <unistd.h>

#ifndef SDP_MSG_DEF_TYPES_H
#define SDP_MSG_DEF_TYPES_H

const uint8_t SDP_V2G_VERSION      = 0x01u;
const uint8_t SDP_V2G_VERSION_NOT  = 0xFEu;
const uint16_t SDP_V2G_REQUEST_TYPE  = 0x9000;
const uint16_t SDP_V2G_RESPONSE_TYPE = 0x9001;
const uint8_t  SDP_V2G_TRANSPORT_TCP= 0x00;
const uint8_t  SDP_V2G_TRANSPORT_UDP= 0x10;
const uint8_t  SDP_V2G_SECURITY_TLS= 0x00;
const uint8_t  SDP_V2G_SECURITY_NONE= 0x10;
const uint32_t SDP_V2G_RESPONSE_LEN  = 20;
const uint32_t SDP_V2G_REQUEST_LEN   = 2;
const uint32_t SDP_V2G_HEADER_LEN   = 8;

// redefine in6_addr to prevent pulling <netinet/in.h> dependencies
typedef uint8_t sdp_in6_addr[16];

typedef struct {
    uint8_t version_std;
    uint8_t version_not;
    uint16_t msg_type;
    uint32_t msg_len;
} sdp_msg_header;

typedef struct  {
    sdp_msg_header header;
    uint8_t security;
    uint8_t transport;
} sdp_request;

typedef struct {
    sdp_msg_header header;
    sdp_in6_addr addr;
    uint16_t port;
    uint8_t security;
    uint8_t transport;
} sdp_response;

int sdp_v2g_decode_req (const uint8_t* buffer, size_t count, sdp_request *request );
int sdp_v2g_encode_req (const sdp_request* request, uint8_t* buffer, size_t count);
int sdp_v2g_decode_res (const uint8_t* buffer, size_t count, sdp_response *response );
int sdp_v2g_encode_res (const sdp_response* response, uint8_t* buffer, size_t count);

#endif