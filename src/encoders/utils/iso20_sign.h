/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: Jose Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifndef ISO20_SIGN_H
#define ISO20_SIGN_H

#include "isox_sign.h"

#include "iso20_AC_Datatypes.h"
#include "iso20_ACDP_Datatypes.h"
#include "iso20_CommonMessages_Datatypes.h"
#include "iso20_DC_Datatypes.h"
#include "iso20_WPT_Datatypes.h"
#include "iso20_AC_Encoder.h"
#include "iso20_ACDP_Encoder.h"
#include "iso20_CommonMessages_Encoder.h"
#include "iso20_DC_Encoder.h"
#include "iso20_WPT_Encoder.h"
#include "iso20_AC_Decoder.h"
#include "iso20_ACDP_Decoder.h"
#include "iso20_CommonMessages_Decoder.h"
#include "iso20_DC_Decoder.h"
#include "iso20_WPT_Decoder.h"

extern
isox_sign_status_t
iso20_sign_check_metering_confirmation_req_signature(
    const struct iso20_exiDocument *message,
    gnutls_pubkey_t pubkey
);

extern
isox_sign_status_t
iso20_sign_check_authorization_req_trust_list(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
);

extern
isox_sign_status_t
iso20_sign_check_authorization_req_root_cert(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
);

extern
isox_sign_status_t
iso20_sign_check_authorization_req_root_path(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
);
#endif