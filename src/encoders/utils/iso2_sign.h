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

#ifndef ISO2_SIGN_H
#define ISO2_SIGN_H
#include "isox_sign.h"

#include "iso2_msgDefDatatypes.h"
#include "iso2_msgDefEncoder.h"
#include "iso2_msgDefDecoder.h"


extern
isox_sign_status_t
iso2_sign_check_authorization_req(
    const struct iso2_exiDocument *document,
    const uint8_t *challenge,
    gnutls_pubkey_t pubkey
);

extern
isox_sign_status_t
iso2_sign_sign_authorization_req(
    struct iso2_exiDocument *document,
    gnutls_privkey_t privkey
);

extern
isox_sign_status_t
iso2_sign_check_metering_receipt_req(
    const struct iso2_exiDocument *document,
    gnutls_pubkey_t pubkey
);

extern
isox_sign_status_t
iso2_sign_sign_metering_receipt_req(
    struct iso2_exiDocument *document,
    gnutls_privkey_t privkey
);

extern
isox_sign_status_t
iso2_sign_check_payment_details_req_trust_list(
    const struct iso2_exiDocument *document,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
);

extern
isox_sign_status_t
iso2_sign_check_payment_details_req_root_cert(
    const struct iso2_exiDocument *document,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
);

extern
isox_sign_status_t
iso2_sign_check_payment_details_req_root_path(
    const struct iso2_exiDocument *document,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
);
#endif