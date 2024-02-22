#include "iso-x-utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
/*
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <ctype.h>

#include <gnutls/x509.h>
*/

#include "iso20_CommonMessages_Datatypes.h"
#include "iso2_msgDefDatatypes.h"

#if iso2_certificateType_BYTES_SIZE > iso20_certificateType_BYTES_SIZE
#define MAX_CERT_SIZE iso2_certificateType_BYTES_SIZE
#else
#define MAX_CERT_SIZE iso20_certificateType_BYTES_SIZE
#endif

/**
 * Loads the certificate at the given path in cert
 *
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_ROOTCERT_OPEN
 *  - ISOX_UTILS_ERROR_ROOTCERT_READ
 *  - ISOX_UTILS_ERROR_ROOTCERT_OVERFLOW
 *  - ISOX_UTILS_ERROR_INTERNAL5
 *  - ISOX_UTILS_ERROR_ROOTCERT_IMPORT
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
isox_utils_load_root_cert(
    const char *path,
    gnutls_x509_crt_t *cert
) {
    int fd, rc;
    ssize_t rsz;
    gnutls_datum_t data;
    uint8_t buffer[MAX_CERT_SIZE + 1];

    /* read the file */
    fd = open(path, O_RDONLY);
    if (fd < 0)
	    return ISOX_UTILS_ERROR_ROOTCERT_OPEN;
    rsz = read(fd, buffer, sizeof buffer);
    close(fd);
    if (rsz < 0)
        return ISOX_UTILS_ERROR_ROOTCERT_READ;
    if ((size_t)rsz > MAX_CERT_SIZE)
        return ISOX_UTILS_ERROR_ROOTCERT_OVERFLOW;

    /* make the certificate */
    rc = gnutls_x509_crt_init(cert);
    if (rc != GNUTLS_E_SUCCESS) {
        return ISOX_UTILS_ERROR_INTERNAL5;
    }
    data.data = buffer;
    data.size = (size_t)rsz;
    rc = gnutls_x509_crt_import(*cert, &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        gnutls_x509_crt_deinit(*cert);
        return ISOX_UTILS_ERROR_ROOTCERT_IMPORT;
    }
    return ISOX_UTILS_DONE;
}

/**
 * Remove memory used by the pubkey
 */
void
isox_utils_drop_pubkey(
    gnutls_pubkey_t *pubkey
) {
    gnutls_pubkey_deinit(*pubkey);
}
