/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: Jose Bolo <jobol@iot.bzh>
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
    ISOX_UTILS_DONE = 0,

    /* 1, 2 */
    ISOX_UTILS_ERROR_ENCODING,
    ISOX_UTILS_ERROR_MAKE_DIGEST,

    /* 3 .. 6 */
    ISOX_UTILS_ERROR_DIGEST,
    ISOX_UTILS_ERROR_DIGEST_LENGTH,
    ISOX_UTILS_ERROR_DIGEST_MISMATCH,
    ISOX_UTILS_ERROR_NOT_SINGLE_SIGNED,        /* there is more than one signed element */

    /* 7 .. 14 */
    ISOX_UTILS_ERROR_NOT_AUTHORIZATION_REQ,
    ISOX_UTILS_ERROR_NOT_METERING_RECEIPT_REQ,
    ISOX_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ,
    ISOX_UTILS_ERROR_NOT_METERING_CONFIRMATION_REQ,
    ISOX_UTILS_ERROR_NOT_PNC_AUTHORIZATION_REQ,
    ISOX_UTILS_ERROR_NO_SIGNATURE,
    ISOX_UTILS_ERROR_NO_CHALLENGE,
    ISOX_UTILS_ERROR_CHALLENGE_SIZE,
    ISOX_UTILS_ERROR_CHALLENGE_MISMATCH,
    ISOX_UTILS_ERROR_BAD_SIGNATURE,

    /* 15 .. 24 */
    ISOX_UTILS_ERROR_CERT_IMPORT,
    ISOX_UTILS_ERROR_SUBCERT_IMPORT,
    ISOX_UTILS_ERROR_ROOTCERT_OPEN,
    ISOX_UTILS_ERROR_ROOTCERT_READ,
    ISOX_UTILS_ERROR_ROOTCERT_OVERFLOW,
    ISOX_UTILS_ERROR_ROOTCERT_IMPORT,
    ISOX_UTILS_ERROR_SUBJECT_CN,
    ISOX_UTILS_ERROR_EMAID_MISMATCH,
    ISOX_UTILS_ERROR_TOO_MANY_CERT,
    ISOX_UTILS_ERROR_INVALID_CERT,

    /* 25 .. 33 */
    ISOX_UTILS_ERROR_INTERNAL1,
    ISOX_UTILS_ERROR_INTERNAL2,
    ISOX_UTILS_ERROR_INTERNAL3,
    ISOX_UTILS_ERROR_INTERNAL4,
    ISOX_UTILS_ERROR_INTERNAL5,
    ISOX_UTILS_ERROR_INTERNAL6,
    ISOX_UTILS_ERROR_INTERNAL7,
    ISOX_UTILS_ERROR_INTERNAL8,
    ISOX_UTILS_ERROR_INTERNAL9
}
    isox_utils_status_t;

extern
isox_utils_status_t
isox_utils_load_root_cert(
    const char *path,
    gnutls_x509_crt_t *cert
);


extern
void
isox_utils_drop_pubkey(
    gnutls_pubkey_t *pubkey
);