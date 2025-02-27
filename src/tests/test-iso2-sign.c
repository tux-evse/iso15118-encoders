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

#include "iso2_sign.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include <gnutls/x509.h>

#define MAX_CERT_SIZE      2000
#define MAX_PRIVKEY_SIZE   2000
#define CHALLENGE_SIZE     16
#define DIGEST_ALGO        GNUTLS_DIG_SHA256
#define DIGEST_MAX_SIZE    32
#define SIGNING_ALGO       GNUTLS_SIGN_ECDSA_SECP256R1_SHA256
#define CHALLENGE          "0123456789abcdef"
#define MAX_EXI_SIZE        8192

/* record of some certification chain */
struct {
	const char *cert, *sub, *root;
} chains[] = {
	{ "end.der", "sub.der", "root.der" },        /* good */
	{ "end2.der", "sub2.der", "root2.der" },     /* good */
	{ "end.der", "sub.der", "root2.der" },       /* bad */
	{ "end2.der", "sub.der", "root.der" },       /* bad */
};

/*
 * structure for holding DER certificate data in tool generated message
 *
 * why the tools didn't define such a structure?
 */
typedef
    struct {
        uint8_t bytes[iso2_certificateType_BYTES_SIZE];
        uint16_t bytesLen;
    }
    certdef;

/* TAP counter */
int ntap = 0;

/* emit TAP overall counters */
void endtap()
{
    printf("1..%d\n", ntap);
}

/* print a TAP line, sts == 0 means NOT OK */
void tap(int sts, const char *fmt, ...)
{
    va_list ap;
    printf("%s %d - ", sts ? "ok" : "not ok", ++ntap);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    putchar('\n');
    va_end(ap);
}

/*
* load file of path in the buffer of size
* returns 0 on error or the length of the read data
*/
size_t
loadbuf(
    const char *path,
    uint8_t *buffer,
    size_t size
) {
    int fd, rc;
    ssize_t rsz;

    /* open the file */
    fd = open(path, O_RDONLY);
    if (fd < 0)
	    return 0;

    /* read the file */
    rsz = read(fd, buffer, size);
    close(fd);

    /* check the read size */
    if (rsz < 0)
	    return 0;
    if ((size_t)rsz >= size)
	    return 0;
    return (size_t)rsz;
}

/*
* load the DER certificate of path in the buffer defined by cdef
* return 0 on success or -1 on error
*/
int loadcertdef(
    const char *path,
    certdef *cdef
) {
    /* read */
    size_t size = loadbuf(path, cdef->bytes, sizeof cdef->bytes);
    if (size == 0)
        return -1;
    /* set the length */
    cdef->bytesLen = (uint16_t)size;
    return 0;
}

/*
* load the DER certificate of path in the gnutls object cert
* return 0 on success or -1 on error
*/
int
loadcert(
    const char *path,
    gnutls_x509_crt_t *cert
) {
    int rc;
    gnutls_datum_t data;
    uint8_t buffer[MAX_CERT_SIZE];

    /* load the certificate */
    size_t size = loadbuf(path, buffer, sizeof buffer);
    if (size == 0)
	    return -1;

    /* make the gnutls certificate object */
    rc = gnutls_x509_crt_init(cert);
    if (rc != GNUTLS_E_SUCCESS)
	    return -1;
    data.data = buffer;
    data.size = size;
    rc = gnutls_x509_crt_import(*cert, &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        gnutls_x509_crt_deinit(*cert);
	    return -1;
    }
    return 0;
}

/*
* load the DER certificate of path and extract its public key definition
* return 0 on success or -1 on error
*/
int
load_pubkey_of_cert(
    const char *path,
    gnutls_pubkey_t *pubkey
) {
    gnutls_x509_crt_t cert;

    /* load the certificate */
    int rc = loadcert(path, &cert);
    if (rc == 0) {
        /* extract its public key */
        rc = gnutls_pubkey_init(pubkey);
        if (rc != GNUTLS_E_SUCCESS)
            rc = -1;
        else {
            rc = gnutls_pubkey_import_x509(*pubkey, cert, 0);
            if (rc == GNUTLS_E_SUCCESS)
                rc = 0;
            else {
                gnutls_pubkey_deinit(*pubkey);
                rc = -1;
            }
        }
    }
    return rc;
}

/*
* load the private key of path
* return 0 on success or -1 on error
*/
int
load_privkey(
    const char *path,
    gnutls_privkey_t *privkey
) {
    int rc;
    gnutls_datum_t data;
    uint8_t buffer[MAX_PRIVKEY_SIZE];
    size_t size = loadbuf(path, buffer, sizeof buffer);
    if (size == 0)
        rc = -1;
    else {
        /* make the private key */
        rc = gnutls_privkey_init(privkey);
        if (rc != GNUTLS_E_SUCCESS)
            rc = -1;
        else {
            data.data = buffer;
            data.size = size;
            rc = gnutls_privkey_import_x509_raw(*privkey, &data, 0, NULL, 0);
            if (rc == GNUTLS_E_SUCCESS)
                rc = 0;
            else {
                gnutls_privkey_deinit(*privkey);
                rc = -1;
            }
        }
    }
    return rc;
}

void do_test_iso2_sign_check_authorization_req(const char *priv, const char *cert, int erc)
{
    int rc;
    struct iso2_exiDocument doc;
    struct iso2_exiFragment fragment;
    gnutls_pubkey_t pubkey;
    gnutls_privkey_t privkey;

    /* forge the test message */
    memset(&doc, 0, sizeof doc);

    init_iso2_V2G_Message(&doc.V2G_Message);
    doc.V2G_Message.Body.AuthorizationReq_isUsed = 1;
    memcpy(doc.V2G_Message.Body.AuthorizationReq.Id.characters, "1234", 4);
    doc.V2G_Message.Body.AuthorizationReq.Id.charactersLen = 4;
    doc.V2G_Message.Body.AuthorizationReq.Id_isUsed = 1;
    memcpy(doc.V2G_Message.Body.AuthorizationReq.GenChallenge.bytes, CHALLENGE, CHALLENGE_SIZE);
    doc.V2G_Message.Body.AuthorizationReq.GenChallenge.bytesLen = CHALLENGE_SIZE;
    doc.V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 1;

    rc = load_privkey(priv, &privkey);
    if (rc == 0) {
        rc = iso2_sign_sign_authorization_req(&doc, privkey);
        if (rc == 0) {
            rc = load_pubkey_of_cert(cert, &pubkey);
            if (rc == 0) {
                rc = iso2_sign_check_authorization_req(&doc, CHALLENGE, pubkey);
                gnutls_pubkey_deinit(pubkey);
            }
        }
    }
    tap(rc == erc, "verification authorization req for %s and %s: found %d, expected %d", priv, cert, rc, erc);
}

void test_iso2_sign_check_authorization_req()
{
    do_test_iso2_sign_check_authorization_req("end.key.der", "end.der", 0);
    do_test_iso2_sign_check_authorization_req("end2.key.der", "end.der", isox_sign_ERROR_BAD_SIGNATURE);
}

void do_test_iso2_sign_check_metering_receipt_req(const char *priv, const char *cert, int erc)
{
    int rc;
    struct iso2_exiDocument doc;
    struct iso2_exiFragment fragment;
    gnutls_pubkey_t pubkey;
    gnutls_privkey_t privkey;

    /* forge the test message */
    memset(&doc, 0, sizeof doc);
    init_iso2_V2G_Message(&doc.V2G_Message);
    doc.V2G_Message.Body.MeteringReceiptReq_isUsed = 1;
    memcpy(doc.V2G_Message.Body.MeteringReceiptReq.Id.characters, "1234", 4);
    doc.V2G_Message.Body.MeteringReceiptReq.Id.charactersLen = 4;
    doc.V2G_Message.Body.MeteringReceiptReq.Id_isUsed = 1;
    memcpy(doc.V2G_Message.Body.MeteringReceiptReq.SessionID.bytes, "1234", 4);
    doc.V2G_Message.Body.MeteringReceiptReq.SessionID.bytesLen = 4;
    doc.V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID = 5;
    doc.V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID_isUsed = 1;

    memcpy(doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters, "abcd", 4);
    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.charactersLen = 4;
    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterReading = 45;
    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterReading_isUsed = 1;

    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterStatus = 1;
    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterStatus_isUsed = 1;

    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.TMeter = 1;
    doc.V2G_Message.Body.MeteringReceiptReq.MeterInfo.TMeter_isUsed = 1;

    /* make signature of the single fragment */
    memset(&fragment, 0, sizeof fragment);
    init_iso2_exiFragment(&fragment);
    fragment.MeteringReceiptReq_isUsed = 1;
    memcpy(&fragment.MeteringReceiptReq, &doc.V2G_Message.Body.MeteringReceiptReq, sizeof fragment.MeteringReceiptReq);

    rc = load_privkey(priv, &privkey);
    if (rc == 0) {
        rc = iso2_sign_sign_metering_receipt_req(&doc, privkey);
        if (rc == 0) {
            rc = load_pubkey_of_cert(cert, &pubkey);
            if (rc == 0) {
                rc = iso2_sign_check_metering_receipt_req(&doc, pubkey);
                gnutls_pubkey_deinit(pubkey);
            }
        }
    }
    tap(rc == erc, "verification metering-receipt req for %s and %s: found %d, expected %d", priv, cert, rc, erc);
}

void test_iso2_sign_check_metering_receipt_req()
{
    do_test_iso2_sign_check_metering_receipt_req("end.key.der", "end.der", 0);
    do_test_iso2_sign_check_metering_receipt_req("end2.key.der", "end.der", isox_sign_ERROR_BAD_SIGNATURE);
}

void do_test_iso2_sign_check_payment_details_req(const char *emaid, int idchain, int erc)
{
    struct iso2_exiDocument doc;
    gnutls_pubkey_t pubkey;
    int rc;

    memset(&doc, 0, sizeof doc);
    init_iso2_V2G_Message(&doc.V2G_Message);
    doc.V2G_Message.Body.PaymentDetailsReq_isUsed = 1;
    doc.V2G_Message.Body.PaymentDetailsReq.eMAID.charactersLen = (uint16_t)strlen(emaid);
    memcpy(doc.V2G_Message.Body.PaymentDetailsReq.eMAID.characters, emaid, doc.V2G_Message.Body.PaymentDetailsReq.eMAID.charactersLen);
    loadcertdef(chains[idchain].cert, (certdef*)&doc.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate);
    doc.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates_isUsed = 1;
    doc.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 1;
    loadcertdef(chains[idchain].sub, (certdef*)&doc.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0]);
    rc = iso2_sign_check_payment_details_req_root_path(&doc, chains[idchain].root, &pubkey);
    tap(rc == erc, "verification of payment details for %s, chain %d: found %d, expected %d", emaid, idchain, rc, erc);
    if (rc == 0)
        isox_sign_drop_pubkey(&pubkey);
}

void test_iso2_sign_check_payment_details_req()
{
    do_test_iso2_sign_check_payment_details_req("", 0, isox_sign_ERROR_EMAID_MISMATCH);
    do_test_iso2_sign_check_payment_details_req("45er-tert-g65", 0, isox_sign_ERROR_EMAID_MISMATCH);
    do_test_iso2_sign_check_payment_details_req("E-M-A--ID", 0, 0);
    do_test_iso2_sign_check_payment_details_req("emaid", 0, 0);
    do_test_iso2_sign_check_payment_details_req("emaid", 1, 0);
    do_test_iso2_sign_check_payment_details_req("emaid", 2, isox_sign_ERROR_INVALID_CERT);
    do_test_iso2_sign_check_payment_details_req("emaid", 3, isox_sign_ERROR_INVALID_CERT);
}

int main(int ac, char **av)
{
    test_iso2_sign_check_payment_details_req();
    test_iso2_sign_check_authorization_req();
    test_iso2_sign_check_metering_receipt_req();
    endtap();
    return 0;
}

