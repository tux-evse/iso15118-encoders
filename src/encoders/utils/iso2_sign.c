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

#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <gnutls/x509.h>

#define MAX_EXI_SIZE        8192
#define DIGEST_ALGO         GNUTLS_DIG_SHA256
#define DIGEST_MAX_SIZE     32
#define CHALLENGE_SIZE      16
#define SIGNING_ALGO        GNUTLS_SIGN_ECDSA_SECP256R1_SHA256
#define MAX_NR_SUB_CERT     iso2_certificateType_4_ARRAY_SIZE
#define MAX_CERT_SIZE       iso2_certificateType_BYTES_SIZE
#define MAX_EMAID_SIZE      iso2_eMAID_CHARACTER_SIZE

/**
 * Compute the hash of the given fragment for the given algo.
 * Store the result in digest that is of size szdigest
 * The length of the computed hash is stored in *dlen
 * Returned status is one of:
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_get_fragment_digest(
    const struct iso2_exiFragment *fragment,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest,
    unsigned *dlen
) {
    unsigned char buffer[MAX_EXI_SIZE];
    exi_bitstream_t stream;
    int rc;

    /* canonisation of the fragment */
    memset(buffer, 0, sizeof buffer);
    memset(&stream, 0, sizeof stream);
    exi_bitstream_init(&stream, buffer, sizeof buffer, 0, NULL);
    rc = encode_iso2_exiFragment(&stream, fragment);
    if (rc != EXI_ERROR__NO_ERROR)
        return isox_sign_ERROR_ENCODING;

    /* check digest length */
    rc = gnutls_hash_get_len(dalgo);
    if (rc < 0 || (unsigned)rc > szdigest)
        return isox_sign_ERROR_INTERNAL1;
    *dlen = (unsigned)rc;

    /* compute the digest */
    rc = gnutls_hash_fast(dalgo, buffer, exi_bitstream_get_length(&stream), digest);
    if (rc != 0)
        return isox_sign_ERROR_MAKE_DIGEST;
    return isox_sign_DONE;
}

/**
 * Compute the hash of the info items of the signature
 * That hash is the data that is then signed.
 * Store the result in digest that is of size szdigest
 * The length of the computed hash is stored in *dlen
 * Returned status is one of:
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_get_signature_digest(
    const struct iso2_SignatureType *signature,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest,
    unsigned *dlen
) {
    struct iso2_exiFragment sig;

    /* create the digest of the signed info of the signature */
    memset(&sig, 0, sizeof sig);
    init_iso2_exiFragment(&sig);
    sig.SignedInfo_isUsed = 1;
    memcpy(&sig.SignedInfo, &signature->SignedInfo, sizeof sig.SignedInfo);
    return iso2_sign_get_fragment_digest(&sig, dalgo, digest, szdigest, dlen);
}


/**
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_SIGN_FAILED
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_sign_single_fragment(
    gnutls_privkey_t privkey,
    struct iso2_MessageHeaderType *header,
    const struct iso2_exiFragment *fragment
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    gnutls_datum_t data, sig;
    isox_sign_status_t sts;

    /* create the digest of the fragment */
    sts = iso2_sign_get_fragment_digest(
                fragment,
                DIGEST_ALGO,
                header->Signature.SignedInfo.Reference.array[0].DigestValue.bytes,
                (unsigned)sizeof header->Signature.SignedInfo.Reference.array[0].DigestValue.bytes,
		&dlen);
    if (sts != isox_sign_DONE)
        return sts;
    header->Signature.SignedInfo.Reference.array[0].DigestValue.bytesLen = (uint16_t)dlen;
    header->Signature.SignedInfo.Reference.arrayLen = 1;

    /* create the digest of the digests */
    sts = iso2_sign_get_signature_digest(
                &header->Signature,
                DIGEST_ALGO,
                digest,
                (unsigned)sizeof digest,
		&dlen);
    if (sts != isox_sign_DONE)
        return sts;

    /* sign the digest of digests */
    data.data = digest;
    data.size = dlen;
    sig.data = NULL;
    sig.size = 0;
    rc = gnutls_privkey_sign_hash2(privkey, SIGNING_ALGO, 0, &data, &sig);
    if (rc != GNUTLS_E_SUCCESS || sig.size > sizeof header->Signature.SignatureValue.CONTENT.bytes) {
        gnutls_free(sig.data);
        return isox_sign_ERROR_SIGN_FAILED;
    }
    memcpy(header->Signature.SignatureValue.CONTENT.bytes, sig.data, sig.size);
    header->Signature.SignatureValue.CONTENT.bytesLen = (uint16_t)sig.size;
    header->Signature_isUsed = 1;
    gnutls_free(sig.data);

    return isox_sign_DONE;
}

/**
 * Checks that the reference digest matches the digest of the fragment
 *
 * CAUTION! No provision is made to check that the reference is done with
 *   - canonisation = http://www.w3.org/TR/canonical-exi/
 *   - transform = http://www.w3.org/TR/canonical-exi/
 *   - digest method = http://www.w3.org/2001/04/xmlenc#sha256
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_DIGEST_LENGTH
 *  - isox_sign_ERROR_DIGEST_MISMATCH
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_fragment_digest(
    const struct iso2_ReferenceType *reference,
    const struct iso2_exiFragment *fragment
) {
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];

    /* get the digest of the fragment */
    int rc = iso2_sign_get_fragment_digest(fragment, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != isox_sign_DONE)
        return rc;

    /* compare with reference */
    if ((unsigned)reference->DigestValue.bytesLen != dlen)
        return isox_sign_ERROR_DIGEST_LENGTH;
    if (memcmp(digest, reference->DigestValue.bytes, dlen) != 0)
        return isox_sign_ERROR_DIGEST_MISMATCH;

    return isox_sign_DONE;
}

/**
 * Checks the public key validates the signature items
 *
 * CAUTION! No provision is made to check that the reference is done with
 *   - canonisation = http://www.w3.org/TR/canonical-exi/
 *   - transform = http://www.w3.org/TR/canonical-exi/
 *   - digest method = http://www.w3.org/2001/04/xmlenc#sha256
 *   - signature method = http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
 *     ()
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_BAD_SIGNATURE
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_signature(
    const struct iso2_SignatureType *signature,
    gnutls_pubkey_t pubkey
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    gnutls_datum_t hash, sign;

    /* create the digest of the signed info of the signature */
    rc = iso2_sign_get_signature_digest(signature, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != isox_sign_DONE)
        return rc;

    /* verify the signature  */
    hash.data = digest;
    hash.size = dlen;
    sign.data = (void*)signature->SignatureValue.CONTENT.bytes;
    sign.size = signature->SignatureValue.CONTENT.bytesLen;
    rc = gnutls_pubkey_verify_hash2(pubkey, SIGNING_ALGO, 0, &hash, &sign);
    if (rc < 0)
        return isox_sign_ERROR_BAD_SIGNATURE;
    return isox_sign_DONE;
}

/**
 * Checks with  the public key that the signature validates the given fragment
 *
 * CAUTION! No provision is made to check that the reference is done with
 *   - canonisation = http://www.w3.org/TR/canonical-exi/
 *   - transform = http://www.w3.org/TR/canonical-exi/
 *   - digest method = http://www.w3.org/2001/04/xmlenc#sha256
 *   - signature method = http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
 *     ()
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_SINGLE_SIGNED
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_BAD_SIGNATURE
 *  - isox_sign_ERROR_DIGEST_LENGTH
 *  - isox_sign_ERROR_DIGEST_MISMATCH
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_single_fragment_signature(
    const struct iso2_SignatureType *signature,
    const struct iso2_exiFragment *fragment,
    gnutls_pubkey_t pubkey
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    struct iso2_exiFragment sig;

    /* check single reference */
    if (signature->SignedInfo.Reference.arrayLen != 1)
    return isox_sign_ERROR_NOT_SINGLE_SIGNED;

    /* check validity of fragment's hash */
    rc = iso2_sign_check_fragment_digest(&signature->SignedInfo.Reference.array[0], fragment);
    if (rc != isox_sign_DONE)
        return rc;

    /* check validity of signed info */
    return iso2_sign_check_signature(signature, pubkey);
}

/**
 * Checks that the AuthorisationReq message has a challenge signed
 * by the given key
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_AUTHORIZATION_REQ
 *  - isox_sign_ERROR_NO_SIGNATURE
 *  - isox_sign_ERROR_NO_CHALLENGE
 *  - isox_sign_ERROR_CHALLENGE_SIZE
 *  - isox_sign_ERROR_CHALLENGE_MISMATCH
 *  - isox_sign_ERROR_NOT_SINGLE_SIGNED
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_BAD_SIGNATURE
 *  - isox_sign_ERROR_DIGEST_LENGTH
 *  - isox_sign_ERROR_DIGEST_MISMATCH
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_authorization_req(
    const struct iso2_exiDocument *document,
    const uint8_t *challenge,
    gnutls_pubkey_t pubkey
) {
    struct iso2_exiFragment fragment;
    const struct iso2_V2G_Message *message= &document->V2G_Message;


    /* validate the request */
    if (message->Body.AuthorizationReq_isUsed == 0)
        return isox_sign_ERROR_NOT_AUTHORIZATION_REQ;
    if (message->Header.Signature_isUsed == 0)
        return isox_sign_ERROR_NO_SIGNATURE;

    /* validate the challenge */
    if (message->Body.AuthorizationReq.GenChallenge_isUsed == 0)
        return isox_sign_ERROR_NO_CHALLENGE;
    if (message->Body.AuthorizationReq.GenChallenge.bytesLen != CHALLENGE_SIZE)
        return isox_sign_ERROR_CHALLENGE_SIZE;
    if (memcmp(message->Body.AuthorizationReq.GenChallenge.bytes, challenge, CHALLENGE_SIZE))
        return isox_sign_ERROR_CHALLENGE_MISMATCH;

    /* initiate the fragment to check */
    init_iso2_exiFragment(&fragment);
    fragment.AuthorizationReq_isUsed = 1u;
    memcpy(&fragment.AuthorizationReq, &message->Body.AuthorizationReq, sizeof fragment.AuthorizationReq);

    /* check the fragment */
    return iso2_sign_check_single_fragment_signature(&message->Header.Signature, &fragment, pubkey);
}

/**
 * Signs the AuthorisationReq message with the given key
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_AUTHORIZATION_REQ
 *  - isox_sign_ERROR_NO_CHALLENGE
 *  - isox_sign_ERROR_CHALLENGE_SIZE
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_SIGN_FAILED
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_sign_authorization_req(
    struct iso2_exiDocument *document,
    gnutls_privkey_t privkey
) {
    struct iso2_exiFragment fragment;
    struct iso2_V2G_Message *message= &document->V2G_Message;


    /* validate the request */
    if (message->Body.AuthorizationReq_isUsed == 0)
        return isox_sign_ERROR_NOT_AUTHORIZATION_REQ;
    if (message->Body.AuthorizationReq.GenChallenge_isUsed == 0)
        return isox_sign_ERROR_NO_CHALLENGE;
    if (message->Body.AuthorizationReq.GenChallenge.bytesLen != CHALLENGE_SIZE)
        return isox_sign_ERROR_CHALLENGE_SIZE;

    /* initiate the fragment to check */
    memset(&fragment, 0, sizeof fragment);
    init_iso2_exiFragment(&fragment);
    fragment.AuthorizationReq_isUsed = 1u;
    memcpy(&fragment.AuthorizationReq, &message->Body.AuthorizationReq, sizeof fragment.AuthorizationReq);

    /* sign the fragment */
    return iso2_sign_sign_single_fragment(privkey, &message->Header, &fragment);
}

/**
 * Checks that the MeteringReceiptReq message is signed
 * by the given key
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_METERING_RECEIPT_REQ
 *  - isox_sign_ERROR_NO_SIGNATURE
 *  - isox_sign_ERROR_NOT_SINGLE_SIGNED
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_BAD_SIGNATURE
 *  - isox_sign_ERROR_DIGEST_LENGTH
 *  - isox_sign_ERROR_DIGEST_MISMATCH
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_metering_receipt_req(
    const struct iso2_exiDocument *document,
    gnutls_pubkey_t pubkey
) {
    struct iso2_exiFragment fragment;
    const struct iso2_V2G_Message *message= &document->V2G_Message;


    /* validate the request */
    if (message->Body.MeteringReceiptReq_isUsed == 0)
        return isox_sign_ERROR_NOT_METERING_RECEIPT_REQ;
    if (message->Header.Signature_isUsed == 0)
        return isox_sign_ERROR_NO_SIGNATURE;

    /* initiate the fragment to check */
    init_iso2_exiFragment(&fragment);
    fragment.MeteringReceiptReq_isUsed = 1u;
    memcpy(&fragment.MeteringReceiptReq, &message->Body.MeteringReceiptReq, sizeof fragment.MeteringReceiptReq);

    /* check the fragment */
    return iso2_sign_check_single_fragment_signature(&message->Header.Signature, &fragment, pubkey);
}

/**
 * Signs the MeteringReceiptReq message with the given key
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_METERING_RECEIPT_REQ
 *  - isox_sign_ERROR_ENCODING
 *  - isox_sign_ERROR_INTERNAL1
 *  - isox_sign_ERROR_SIGN_FAILED
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_sign_metering_receipt_req(
    struct iso2_exiDocument *document,
    gnutls_privkey_t privkey
) {
    struct iso2_exiFragment fragment;
    struct iso2_V2G_Message *message= &document->V2G_Message;


    /* validate the request */
    if (message->Body.MeteringReceiptReq_isUsed == 0)
        return isox_sign_ERROR_NOT_METERING_RECEIPT_REQ;

    /* initiate the fragment to check */
    memset(&fragment, 0, sizeof fragment);
    init_iso2_exiFragment(&fragment);
    fragment.MeteringReceiptReq_isUsed = 1u;
    memcpy(&fragment.MeteringReceiptReq, &message->Body.MeteringReceiptReq, sizeof fragment.MeteringReceiptReq);

    /* check the fragment */
    return iso2_sign_sign_single_fragment(privkey, &message->Header, &fragment);
}

/**
 * Compares the 2 given EMAID and returns 0 if they are not equals
 * or of length null or return the length of the EMAID without decoration.
 * Decoration is made of dashes separating groups.
 */
unsigned
compare_emaid(
    const uint8_t *buf1,
    unsigned len1,
    const uint8_t *buf2,
    unsigned len2
) {
    unsigned len = 0, idx1 = 0, idx2 = 0;
    while (idx1 < len1 && idx2 < len2) {
        if (buf1[idx1] == '-')
            idx1++;
        else if (buf2[idx2] == '-')
            idx2++;
        else if (toupper(buf1[idx1]) != toupper(buf2[idx2]))
            return 0;
        else {
            idx1++;
            idx2++;
            len++;
        }
    }
    while (idx1 < len1 && buf1[idx1] == '-')
        idx1++;
    while (idx2 < len2 && buf2[idx2] == '-')
        idx2++;
    return idx1 == len1 && idx2 == len2 ? len : 0;
}

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_SUBJECT_CN
 *  - isox_sign_ERROR_EMAID_MISMATCH
 *  - isox_sign_ERROR_TOO_MANY_CERT
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_INVALID_CERT
 *  - isox_sign_ERROR_INTERNAL2
 *  - isox_sign_ERROR_INTERNAL3
 *  - isox_sign_ERROR_INTERNAL7
 *  - isox_sign_ERROR_INTERNAL8
 *  - isox_sign_ERROR_INTERNAL9;
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_payment_details_req_trust_list(
    const struct iso2_exiDocument *document,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
) {
    const struct iso2_V2G_Message *message= &document->V2G_Message;
    int rc;
    unsigned idx, cnt, len, vsts, ncerts = 0;
    gnutls_x509_crt_t certs[MAX_NR_SUB_CERT + 1];
    gnutls_datum_t data;
    const struct iso2_PaymentDetailsReqType *msgreq;
    const struct iso2_CertificateChainType *msgcert;
    gnutls_x509_dn_t gdn;
	uint8_t emaid[MAX_EMAID_SIZE];
    size_t emaidsz;

    /* validate the request */
    if (message->Body.PaymentDetailsReq_isUsed == 0)
        return isox_sign_ERROR_NOT_PAYEMENT_DETAIL_REQ;
    msgreq = &message->Body.PaymentDetailsReq;
    msgcert = &msgreq->ContractSignatureCertChain;

    /* import the certificate */
    rc = gnutls_x509_crt_init(&certs[0]);
    if (rc != GNUTLS_E_SUCCESS)
        return isox_sign_ERROR_INTERNAL2;
    ncerts = 1;
    data.data = (void*)msgcert->Certificate.bytes;
    data.size = msgcert->Certificate.bytesLen;
    rc = gnutls_x509_crt_import(certs[0], &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        rc = isox_sign_ERROR_CERT_IMPORT;
        goto cleanup;
    }

    /* validate the eMAID */
    emaidsz = sizeof emaid;
    rc = gnutls_x509_crt_get_dn_by_oid(certs[0], GNUTLS_OID_X520_COMMON_NAME, 0, 0, emaid, &emaidsz);
    if (rc < 0) {
        rc = isox_sign_ERROR_SUBJECT_CN;
        goto cleanup;
    }
    len = compare_emaid(emaid, (unsigned) emaidsz, msgreq->eMAID.characters, (unsigned)msgreq->eMAID.charactersLen);
    if (len == 0)  {
        rc = isox_sign_ERROR_EMAID_MISMATCH;
        goto cleanup;
    }

    /* import the sub certificates */
    cnt = msgcert->SubCertificates_isUsed ? msgcert->SubCertificates.Certificate.arrayLen : 0;
    if (cnt > MAX_NR_SUB_CERT) {
        rc = isox_sign_ERROR_TOO_MANY_CERT;
        goto cleanup;
    }
    for (idx = 0 ; idx < cnt ; idx++) {
        rc = gnutls_x509_crt_init(&certs[ncerts]);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = isox_sign_ERROR_INTERNAL3;
            goto cleanup;
        }
        data.data = (void*)msgcert->SubCertificates.Certificate.array[idx].bytes;
        data.size = msgcert->SubCertificates.Certificate.array[idx].bytesLen;
        rc = gnutls_x509_crt_import(certs[ncerts++], &data, GNUTLS_X509_FMT_DER);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = isox_sign_ERROR_CERT_IMPORT;
            goto cleanup;
        }
    }

    /* check the trust chain */
    vsts = 0;
    rc = gnutls_x509_trust_list_verify_crt(trust_list, certs, ncerts, 0, &vsts, NULL);
    if (rc != GNUTLS_E_SUCCESS)
            rc = isox_sign_ERROR_INTERNAL7;
    else if (vsts & GNUTLS_CERT_INVALID)
            rc = isox_sign_ERROR_INVALID_CERT;
    else
            rc = isox_sign_DONE;
    if (rc != isox_sign_DONE)
        goto cleanup;

    /* extract the public key */
    if (pubkey != NULL) {
        rc = gnutls_pubkey_init(pubkey);
        if (rc != GNUTLS_E_SUCCESS)
            rc = isox_sign_ERROR_INTERNAL8;
        else {
            rc = gnutls_pubkey_import_x509(*pubkey, certs[0], 0);
            if (rc == GNUTLS_E_SUCCESS)
                rc = isox_sign_DONE;
            else {
                gnutls_pubkey_deinit(*pubkey);
                rc = isox_sign_ERROR_INTERNAL9;
            }
        }
    }

    /* cleanup */
cleanup:
    while (ncerts > 0)
        gnutls_x509_crt_deinit(certs[--ncerts]);
    return rc;
}

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_SUBJECT_CN
 *  - isox_sign_ERROR_EMAID_MISMATCH
 *  - isox_sign_ERROR_TOO_MANY_CERT
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_INVALID_CERT
 *  - isox_sign_ERROR_INTERNAL2
 *  - isox_sign_ERROR_INTERNAL3
 *  - isox_sign_ERROR_INTERNAL4
 *  - isox_sign_ERROR_INTERNAL6
 *  - isox_sign_ERROR_INTERNAL7
 *  - isox_sign_ERROR_INTERNAL8
 *  - isox_sign_ERROR_INTERNAL9;
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_payment_details_req_root_cert(
    const struct iso2_exiDocument *document,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_trust_list_t trust_list;

    /* initiate the trust list */
    rc = gnutls_x509_trust_list_init(&trust_list, 1);
    if (rc != GNUTLS_E_SUCCESS)
        return isox_sign_ERROR_INTERNAL4;
    rc = gnutls_x509_trust_list_add_cas(trust_list, &root_cert, 1, 0);
    if (rc != 1)
        rc = isox_sign_ERROR_INTERNAL6;
    else
        /* check the trust list */
        rc = iso2_sign_check_payment_details_req_trust_list(document, trust_list, pubkey);
    gnutls_x509_trust_list_deinit(trust_list, 0);
    return rc;
}

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - isox_sign_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_SUBJECT_CN
 *  - isox_sign_ERROR_EMAID_MISMATCH
 *  - isox_sign_ERROR_TOO_MANY_CERT
 *  - isox_sign_ERROR_CERT_IMPORT
 *  - isox_sign_ERROR_INVALID_CERT
 *  - isox_sign_ERROR_ROOTCERT_OPEN
 *  - isox_sign_ERROR_ROOTCERT_READ
 *  - isox_sign_ERROR_ROOTCERT_OVERFLOW
 *  - isox_sign_ERROR_ROOTCERT_IMPORT
 *  - isox_sign_ERROR_INTERNAL2
 *  - isox_sign_ERROR_INTERNAL3
 *  - isox_sign_ERROR_INTERNAL4
 *  - isox_sign_ERROR_INTERNAL5
 *  - isox_sign_ERROR_INTERNAL6
 *  - isox_sign_ERROR_INTERNAL7
 *  - isox_sign_ERROR_INTERNAL8
 *  - isox_sign_ERROR_INTERNAL9;
 *  - isox_sign_DONE
 */
isox_sign_status_t
iso2_sign_check_payment_details_req_root_path(
    const struct iso2_exiDocument *document,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_crt_t root_cert;

    /* import the root certificate */
    rc = isox_sign_load_root_cert(root_cert_path, &root_cert);
    if (rc == isox_sign_DONE) {
        rc = iso2_sign_check_payment_details_req_root_cert(document, root_cert, pubkey);
        gnutls_x509_crt_deinit(root_cert);
    }
    return rc;
}
