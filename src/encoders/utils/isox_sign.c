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

#include "isox_sign.h"

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
 *  - isox_sign_ERROR_ROOTCERT_OPEN
 *  - isox_sign_ERROR_ROOTCERT_READ
 *  - isox_sign_ERROR_ROOTCERT_OVERFLOW
 *  - isox_sign_ERROR_INTERNAL5
 *  - isox_sign_ERROR_ROOTCERT_IMPORT
 *  - isox_sign_DONE
 */
isox_sign_status_t
isox_sign_load_root_cert(
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
	    return isox_sign_ERROR_ROOTCERT_OPEN;
    rsz = read(fd, buffer, sizeof buffer);
    close(fd);
    if (rsz < 0)
        return isox_sign_ERROR_ROOTCERT_READ;
    if ((size_t)rsz > MAX_CERT_SIZE)
        return isox_sign_ERROR_ROOTCERT_OVERFLOW;

    /* make the certificate */
    rc = gnutls_x509_crt_init(cert);
    if (rc != GNUTLS_E_SUCCESS) {
        return isox_sign_ERROR_INTERNAL5;
    }
    data.data = buffer;
    data.size = (size_t)rsz;
    rc = gnutls_x509_crt_import(*cert, &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        gnutls_x509_crt_deinit(*cert);
        return isox_sign_ERROR_ROOTCERT_IMPORT;
    }
    return isox_sign_DONE;
}

/**
 * Remove memory used by the pubkey
 */
void
isox_sign_drop_pubkey(
    gnutls_pubkey_t *pubkey
) {
    gnutls_pubkey_deinit(*pubkey);
}
