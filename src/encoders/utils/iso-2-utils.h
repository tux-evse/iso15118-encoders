#include "iso-x-utils.h"

#include "iso2_msgDefDatatypes.h"
#include "iso2_msgDefEncoder.h"
#include "iso2_msgDefDecoder.h"


extern
isox_utils_status_t
iso2_utils_check_authorization_req_signature(
    const struct iso2_V2G_Message *message,
    const uint8_t *challenge,
    gnutls_pubkey_t pubkey
);

extern
isox_utils_status_t
iso2_utils_check_metering_receipt_req_signature(
    const struct iso2_V2G_Message *message,
    gnutls_pubkey_t pubkey
);

extern
isox_utils_status_t
iso2_utils_check_payment_details_req_trust_list(
    const struct iso2_V2G_Message *message,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
);

extern
isox_utils_status_t
iso2_utils_check_payment_details_req_root_cert(
    const struct iso2_V2G_Message *message,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
);

extern
isox_utils_status_t
iso2_utils_check_payment_details_req_root_path(
    const struct iso2_V2G_Message *message,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
);
