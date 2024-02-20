
#include "exi_basetypes.h"
#include "exi_basetypes_encoder.h"
#include "exi_error_codes.h"
#include "exi_header.h"
#include "iso2_msgDefDatatypes.h"
#include "iso2_msgDefEncoder.h"
#include "iso2_msgDefDecoder.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

typedef enum {
    ISO2_UTILS_DONE = 0,

    /* 1, 2 */
    ISO2_UTILS_ERROR_ENCODING,
    ISO2_UTILS_ERROR_MAKE_DIGEST,

    /* 3 .. 6 */
    ISO2_UTILS_ERROR_DIGEST,
    ISO2_UTILS_ERROR_DIGEST_LENGTH,
    ISO2_UTILS_ERROR_DIGEST_MISMATCH,
    ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED,        /* there is more than one signed element */

    /* 7 .. 14 */
    ISO2_UTILS_ERROR_NOT_AUTHORIZATION_REQ,
    ISO2_UTILS_ERROR_NOT_METERING_RECEIPT_REQ,
    ISO2_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ,
    ISO2_UTILS_ERROR_NO_SIGNATURE,
    ISO2_UTILS_ERROR_NO_CHALLENGE,
    ISO2_UTILS_ERROR_CHALLENGE_SIZE,
    ISO2_UTILS_ERROR_CHALLENGE_MISMATCH,
    ISO2_UTILS_ERROR_BAD_SIGNATURE,

    /* 15 .. 24 */
    ISO2_UTILS_ERROR_CERT_IMPORT,
    ISO2_UTILS_ERROR_SUBCERT_IMPORT,
    ISO2_UTILS_ERROR_ROOTCERT_OPEN,
    ISO2_UTILS_ERROR_ROOTCERT_READ,
    ISO2_UTILS_ERROR_ROOTCERT_OVERFLOW,
    ISO2_UTILS_ERROR_ROOTCERT_IMPORT,
    ISO2_UTILS_ERROR_SUBJECT_CN,
    ISO2_UTILS_ERROR_EMAID_MISMATCH,
    ISO2_UTILS_ERROR_TOO_MANY_CERT,
    ISO2_UTILS_ERROR_INVALID_CERT,

    /* 25 .. 33 */
    ISO2_UTILS_ERROR_INTERNAL1,
    ISO2_UTILS_ERROR_INTERNAL2,
    ISO2_UTILS_ERROR_INTERNAL3,
    ISO2_UTILS_ERROR_INTERNAL4,
    ISO2_UTILS_ERROR_INTERNAL5,
    ISO2_UTILS_ERROR_INTERNAL6,
    ISO2_UTILS_ERROR_INTERNAL7,
    ISO2_UTILS_ERROR_INTERNAL8,
    ISO2_UTILS_ERROR_INTERNAL9
}
    iso2_utils_status_t;

extern
iso2_utils_status_t
iso2_utils_check_authorization_req_signature(
    const struct iso2_V2G_Message *message,
    const uint8_t *challenge,
    gnutls_pubkey_t pubkey
);

extern
iso2_utils_status_t
iso2_utils_check_metering_receipt_req_signature(
    const struct iso2_V2G_Message *message,
    gnutls_pubkey_t pubkey
);

extern
iso2_utils_status_t
iso2_utils_check_payment_details_req_trust_list(
    const struct iso2_V2G_Message *message,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
);

extern
iso2_utils_status_t
iso2_utils_check_payment_details_req_root_cert(
    const struct iso2_V2G_Message *message,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
);

extern
iso2_utils_status_t
iso2_utils_check_payment_details_req_root_path(
    const struct iso2_V2G_Message *message,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
);

extern
void
iso2_utils_drop_pubkey(
    gnutls_pubkey_t *pubkey
);
