
#include "iso-x-utils.h"

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
isox_utils_status_t
iso20_utils_check_metering_confirmation_req_signature(
    const struct iso20_exiDocument *message,
    gnutls_pubkey_t pubkey
);

extern
isox_utils_status_t
iso20_utils_check_authorization_req_trust_list(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
);

extern
isox_utils_status_t
iso20_utils_check_authorization_req_root_cert(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
);

extern
isox_utils_status_t
iso20_utils_check_authorization_req_root_path(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
);
