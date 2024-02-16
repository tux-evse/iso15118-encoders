
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

	ISO2_UTILS_ERROR_ENCODING,
	ISO2_UTILS_ERROR_INTERNAL1,
	ISO2_UTILS_ERROR_MAKE_DIGEST,

	ISO2_UTILS_ERROR_DIGEST,
	ISO2_UTILS_ERROR_DIGEST_LENGTH,
	ISO2_UTILS_ERROR_DIGEST_MISMATCH,

	ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED,		/* there is more than one signed element */

	ISO2_UTILS_ERROR_NOT_AUTHORIZATION_REQ,
	ISO2_UTILS_ERROR_NOT_METERING_RECEIPT_REQ,
	ISO2_UTILS_ERROR_NO_SIGNATURE,
	ISO2_UTILS_ERROR_NO_CHALLENGE,
	ISO2_UTILS_ERROR_CHALLENGE_SIZE,
	ISO2_UTILS_ERROR_CHALLENGE_MISMATCH,

	ISO2_UTILS_ERROR_BAD_SIGNATURE
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
	const uint8_t *challenge,
        gnutls_pubkey_t pubkey
);
