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

#include "exi_basetypes.h"
#include "exi_basetypes_encoder.h"
#include "exi_error_codes.h"
#include "exi_header.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

typedef enum {
    isox_sign_DONE = 0,

    /* 1, 2 */
    isox_sign_ERROR_ENCODING,
    isox_sign_ERROR_MAKE_DIGEST,

    /* 3 .. 6 */
    isox_sign_ERROR_DIGEST,
    isox_sign_ERROR_DIGEST_LENGTH,
    isox_sign_ERROR_DIGEST_MISMATCH,
    isox_sign_ERROR_NOT_SINGLE_SIGNED,        /* there is more than one signed element */

    /* 7 .. 14 */
    isox_sign_ERROR_NOT_AUTHORIZATION_REQ,
    isox_sign_ERROR_NOT_METERING_RECEIPT_REQ,
    isox_sign_ERROR_NOT_PAYEMENT_DETAIL_REQ,
    isox_sign_ERROR_NOT_METERING_CONFIRMATION_REQ,
    isox_sign_ERROR_NOT_PNC_AUTHORIZATION_REQ,
    isox_sign_ERROR_NO_SIGNATURE,
    isox_sign_ERROR_NO_CHALLENGE,
    isox_sign_ERROR_CHALLENGE_SIZE,
    isox_sign_ERROR_CHALLENGE_MISMATCH,
    isox_sign_ERROR_BAD_SIGNATURE,

    /* 15 .. 24 */
    isox_sign_ERROR_CERT_IMPORT,
    isox_sign_ERROR_SUBCERT_IMPORT,
    isox_sign_ERROR_ROOTCERT_OPEN,
    isox_sign_ERROR_ROOTCERT_READ,
    isox_sign_ERROR_ROOTCERT_OVERFLOW,
    isox_sign_ERROR_ROOTCERT_IMPORT,
    isox_sign_ERROR_SUBJECT_CN,
    isox_sign_ERROR_EMAID_MISMATCH,
    isox_sign_ERROR_TOO_MANY_CERT,
    isox_sign_ERROR_INVALID_CERT,

    /* 25 .. 33 */
    isox_sign_ERROR_INTERNAL1,
    isox_sign_ERROR_INTERNAL2,
    isox_sign_ERROR_INTERNAL3,
    isox_sign_ERROR_INTERNAL4,
    isox_sign_ERROR_INTERNAL5,
    isox_sign_ERROR_INTERNAL6,
    isox_sign_ERROR_INTERNAL7,
    isox_sign_ERROR_INTERNAL8,
    isox_sign_ERROR_INTERNAL9
}
    isox_sign_status_t;

extern
isox_sign_status_t
isox_sign_load_root_cert(
    const char *path,
    gnutls_x509_crt_t *cert
);


extern
void
isox_sign_drop_pubkey(
    gnutls_pubkey_t *pubkey
);
