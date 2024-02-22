
#include "iso-20-utils.h"

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
#define MAX_NR_SUB_CERT     iso20_certificateType_3_ARRAY_SIZE
#define MAX_CERT_SIZE       iso20_certificateType_BYTES_SIZE    
#define MAX_EMAID_SIZE      iso20_EMAID_CHARACTER_SIZE

/**
 * Compute the hash of the given fragment for the given algo.
 * Store the result in digest that is of size szdigest
 * The length of the computed hash is stored in *dlen
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_get_fragment_digest(
    const struct iso20_exiFragment *fragment,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest,
    unsigned *dlen
) {
    unsigned char buffer[MAX_EXI_SIZE];
    exi_bitstream_t stream;
    int rc;

    /* canonisation of the fragment */
    exi_bitstream_init(&stream, buffer, sizeof buffer, 0, NULL);
    rc = encode_iso20_exiFragment(&stream, (struct iso20_exiFragment*)fragment);
    if (rc != EXI_ERROR__NO_ERROR)
        return ISOX_UTILS_ERROR_ENCODING;

    /* check digest length */
    rc = gnutls_hash_get_len(dalgo);
    if (rc < 0 || (unsigned)rc > szdigest)
        return ISOX_UTILS_ERROR_INTERNAL1;
    *dlen = (unsigned)rc;

    /* compute the digest */
    rc = gnutls_hash_fast(dalgo, buffer, exi_bitstream_get_length(&stream), digest);
    if (rc != 0)
        return ISOX_UTILS_ERROR_MAKE_DIGEST;
    return ISOX_UTILS_DONE;
}

/**
 * Compute the hash of the info items of the signature
 * That hash is the data that is then signed.
 * Store the result in digest that is of size szdigest
 * The length of the computed hash is stored in *dlen
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_get_signature_digest(
    const struct iso20_SignatureType *signature,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest,
    unsigned *dlen
) {
    struct iso20_exiFragment sig;

    /* create the digest of the signed info of the signature */
    init_iso20_exiFragment(&sig);
    sig.SignedInfo_isUsed = 1;
    memcpy(&sig.SignedInfo, &signature->SignedInfo, sizeof sig.SignedInfo);
    return iso20_utils_get_fragment_digest(&sig, dalgo, digest, szdigest, dlen);
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
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_ERROR_DIGEST_LENGTH
 *  - ISOX_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_fragment_digest(
    const struct iso20_ReferenceType *reference,
    const struct iso20_exiFragment *fragment
) {
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];

    /* get the digest of the fragment */
    int rc = iso20_utils_get_fragment_digest(fragment, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != ISOX_UTILS_DONE)
        return rc;

    /* compare with reference */
    if ((unsigned)reference->DigestValue.bytesLen != dlen)
        return ISOX_UTILS_ERROR_DIGEST_LENGTH;
    if (memcmp(digest, reference->DigestValue.bytes, dlen) != 0)
        return ISOX_UTILS_ERROR_DIGEST_MISMATCH;

    return ISOX_UTILS_DONE;
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
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_ERROR_BAD_SIGNATURE
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_signature(
    const struct iso20_SignatureType *signature,
    gnutls_pubkey_t pubkey
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    gnutls_datum_t hash, sign;

    /* create the digest of the signed info of the signature */
    rc = iso20_utils_get_signature_digest(signature, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != ISOX_UTILS_DONE)
        return rc;

    /* verify the signature  */
    hash.data = digest;
    hash.size = dlen;
    sign.data = (void*)signature->SignatureValue.CONTENT.bytes;
    sign.size = signature->SignatureValue.CONTENT.bytesLen;
    rc = gnutls_pubkey_verify_hash2(pubkey, SIGNING_ALGO, 0, &hash, &sign);
    if (rc < 0)
        return ISOX_UTILS_ERROR_BAD_SIGNATURE;
    return ISOX_UTILS_DONE;
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
 *  - ISOX_UTILS_ERROR_NOT_SINGLE_SIGNED
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_ERROR_BAD_SIGNATURE
 *  - ISOX_UTILS_ERROR_DIGEST_LENGTH
 *  - ISOX_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_single_fragment_signature(
    const struct iso20_SignatureType *signature,
    const struct iso20_exiFragment *fragment,
    gnutls_pubkey_t pubkey
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    struct iso20_exiFragment sig;

    /* check single reference */
    if (signature->SignedInfo.Reference.arrayLen != 1)
    return ISOX_UTILS_ERROR_NOT_SINGLE_SIGNED;

    /* check validity of fragment's hash */
    rc = iso20_utils_check_fragment_digest(&signature->SignedInfo.Reference.array[0], fragment);
    if (rc != ISOX_UTILS_DONE)
        return rc;

    /* check validity of signed info */
    return iso20_utils_check_signature(signature, pubkey);
}


/**
 * Checks that the MeteringConfirmationReq message is signed
 * by the given key
 *
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_NOT_METERING_RECEIPT_REQ
 *  - ISOX_UTILS_ERROR_NO_SIGNATURE
 *  - ISOX_UTILS_ERROR_NOT_SINGLE_SIGNED
 *  - ISOX_UTILS_ERROR_ENCODING
 *  - ISOX_UTILS_ERROR_INTERNAL1
 *  - ISOX_UTILS_ERROR_BAD_SIGNATURE
 *  - ISOX_UTILS_ERROR_DIGEST_LENGTH
 *  - ISOX_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_metering_confirmation_req_signature(
    const struct iso20_exiDocument *message,
    gnutls_pubkey_t pubkey
) {
    struct iso20_exiFragment fragment;
    const struct iso20_MeteringConfirmationReqType *msg;

    /* validate the request */
    if (message->MeteringConfirmationReq_isUsed == 0)
        return ISOX_UTILS_ERROR_NOT_METERING_CONFIRMATION_REQ;
    msg = &message->MeteringConfirmationReq;
    if (msg->Header.Signature_isUsed == 0)
        return ISOX_UTILS_ERROR_NO_SIGNATURE;

    /* initiate the fragment to check */
    init_iso20_exiFragment(&fragment);
    fragment.MeteringConfirmationReq_isUsed = 1u;
    memcpy(&fragment.MeteringConfirmationReq, &msg, sizeof fragment.MeteringConfirmationReq);

    /* check the fragment */
    return iso20_utils_check_single_fragment_signature(&msg->Header.Signature, &fragment, pubkey);
}

#if 0
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
#endif

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_SUBJECT_CN
 *  - ISOX_UTILS_ERROR_EMAID_MISMATCH
 *  - ISOX_UTILS_ERROR_TOO_MANY_CERT
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_INVALID_CERT
 *  - ISOX_UTILS_ERROR_INTERNAL2
 *  - ISOX_UTILS_ERROR_INTERNAL3
 *  - ISOX_UTILS_ERROR_INTERNAL7
 *  - ISOX_UTILS_ERROR_INTERNAL8
 *  - ISOX_UTILS_ERROR_INTERNAL9;
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_authorization_req_trust_list(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    unsigned idx, cnt, len, vsts, ncerts = 0;
    struct iso20_exiFragment fragment;
    gnutls_x509_crt_t certs[MAX_NR_SUB_CERT + 1];
    gnutls_datum_t data;
    const struct iso20_AuthorizationReqType *msg;
    const struct iso20_ContractCertificateChainType *mcert;
    gnutls_x509_dn_t gdn;

    /* ensure not garbage */
    if (pubkey != NULL)
        *pubkey = NULL;

    /* validate the request */
    if (message->AuthorizationReq_isUsed == 0)
        return ISOX_UTILS_ERROR_NOT_AUTHORIZATION_REQ;
    msg = &message->AuthorizationReq;
    if (msg->PnC_AReqAuthorizationMode_isUsed == 0)
        return ISOX_UTILS_ERROR_NOT_PNC_AUTHORIZATION_REQ;
    if (msg->Header.Signature_isUsed == 0)
        return ISOX_UTILS_ERROR_NO_SIGNATURE;

    /* import the certificate */
    rc = gnutls_x509_crt_init(&certs[0]);
    if (rc != GNUTLS_E_SUCCESS)
        return ISOX_UTILS_ERROR_INTERNAL2;
    ncerts = 1;
    mcert = &msg->PnC_AReqAuthorizationMode.ContractCertificateChain;
    data.data = (void*)mcert->Certificate.bytes;
    data.size = mcert->Certificate.bytesLen;
    rc = gnutls_x509_crt_import(certs[0], &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        rc = ISOX_UTILS_ERROR_CERT_IMPORT;
        goto cleanup;
    }

#if 0
    /* validate the eMAID */
    uint8_t emaid[MAX_EMAID_SIZE];
    size_t emaidsz;
    emaidsz = sizeof emaid;
    rc = gnutls_x509_crt_get_dn_by_oid(certs[0], GNUTLS_OID_X520_COMMON_NAME, 0, 0, emaid, &emaidsz);
    if (rc < 0) {
        rc = ISOX_UTILS_ERROR_SUBJECT_CN;
        goto cleanup;
    }
    len = compare_emaid(emaid, (unsigned) emaidsz, msg->eMAID.characters, (unsigned)msg->eMAID.charactersLen);
    if (len == 0)  {
        rc = ISOX_UTILS_ERROR_EMAID_MISMATCH;
        goto cleanup;
    }
#endif

    /* import the sub certificates */
    cnt = mcert->SubCertificates.Certificate.arrayLen;
    if (cnt > MAX_NR_SUB_CERT) {
        rc = ISOX_UTILS_ERROR_TOO_MANY_CERT;
        goto cleanup;
    }
    for (idx = 0 ; idx < cnt ; idx++) {
        rc = gnutls_x509_crt_init(&certs[ncerts]);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = ISOX_UTILS_ERROR_INTERNAL3;
            goto cleanup;
        }
        data.data = (void*)mcert->SubCertificates.Certificate.array[idx].bytes;
        data.size = mcert->SubCertificates.Certificate.array[idx].bytesLen;
        rc = gnutls_x509_crt_import(certs[ncerts++], &data, GNUTLS_X509_FMT_DER);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = ISOX_UTILS_ERROR_CERT_IMPORT;
            goto cleanup;
        }
    }

    /* check the trust chain */
    vsts = 0;
    rc = gnutls_x509_trust_list_verify_crt(trust_list, certs, ncerts, 0, &vsts, NULL);
    if (rc != GNUTLS_E_SUCCESS)
            rc = ISOX_UTILS_ERROR_INTERNAL7;
    else if (vsts & GNUTLS_CERT_INVALID)
            rc = ISOX_UTILS_ERROR_INVALID_CERT;
    else
            rc = ISOX_UTILS_DONE;
    if (rc != ISOX_UTILS_DONE)
        goto cleanup;

    /* extract the public key */
    if (pubkey != NULL) {
        rc = gnutls_pubkey_init(pubkey);
        if (rc != GNUTLS_E_SUCCESS)
            rc = ISOX_UTILS_ERROR_INTERNAL8;
        else {
            rc = gnutls_pubkey_import_x509(*pubkey, certs[0], 0);
            if (rc != GNUTLS_E_SUCCESS)
                rc = ISOX_UTILS_ERROR_INTERNAL9;
            else {
                /* check signature of the message */
                init_iso20_exiFragment(&fragment);
                fragment.PnC_AReqAuthorizationMode_isUsed = 1u;
                memcpy(&fragment.PnC_AReqAuthorizationMode, &msg->PnC_AReqAuthorizationMode,
                            sizeof fragment.PnC_AReqAuthorizationMode);
                rc = iso20_utils_check_single_fragment_signature(&msg->Header.Signature,
                            &fragment, *pubkey);
            }
            if (rc != ISOX_UTILS_DONE)
                gnutls_pubkey_deinit(*pubkey);
        }
        if (rc != ISOX_UTILS_DONE)
            *pubkey = NULL;
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
 *  - ISOX_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_SUBJECT_CN
 *  - ISOX_UTILS_ERROR_EMAID_MISMATCH
 *  - ISOX_UTILS_ERROR_TOO_MANY_CERT
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_INVALID_CERT
 *  - ISOX_UTILS_ERROR_INTERNAL2
 *  - ISOX_UTILS_ERROR_INTERNAL3
 *  - ISOX_UTILS_ERROR_INTERNAL4
 *  - ISOX_UTILS_ERROR_INTERNAL6
 *  - ISOX_UTILS_ERROR_INTERNAL7
 *  - ISOX_UTILS_ERROR_INTERNAL8
 *  - ISOX_UTILS_ERROR_INTERNAL9;
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_authorization_req_root_cert(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_trust_list_t trust_list;

    /* initiate the trust list */
    rc = gnutls_x509_trust_list_init(&trust_list, 1);
    if (rc != GNUTLS_E_SUCCESS)
        return ISOX_UTILS_ERROR_INTERNAL4;
    rc = gnutls_x509_trust_list_add_cas(trust_list, &root_cert, 1, 0);
    if (rc != 1)
        rc = ISOX_UTILS_ERROR_INTERNAL6;
    else
        /* check the trust list */
        rc = iso20_utils_check_authorization_req_trust_list(message, challenge, trust_list, pubkey);
    gnutls_x509_trust_list_deinit(trust_list, 0);
    return rc;
}

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - ISOX_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_SUBJECT_CN
 *  - ISOX_UTILS_ERROR_EMAID_MISMATCH
 *  - ISOX_UTILS_ERROR_TOO_MANY_CERT
 *  - ISOX_UTILS_ERROR_CERT_IMPORT
 *  - ISOX_UTILS_ERROR_INVALID_CERT
 *  - ISOX_UTILS_ERROR_ROOTCERT_OPEN
 *  - ISOX_UTILS_ERROR_ROOTCERT_READ
 *  - ISOX_UTILS_ERROR_ROOTCERT_OVERFLOW
 *  - ISOX_UTILS_ERROR_ROOTCERT_IMPORT
 *  - ISOX_UTILS_ERROR_INTERNAL2
 *  - ISOX_UTILS_ERROR_INTERNAL3
 *  - ISOX_UTILS_ERROR_INTERNAL4
 *  - ISOX_UTILS_ERROR_INTERNAL5
 *  - ISOX_UTILS_ERROR_INTERNAL6
 *  - ISOX_UTILS_ERROR_INTERNAL7
 *  - ISOX_UTILS_ERROR_INTERNAL8
 *  - ISOX_UTILS_ERROR_INTERNAL9;
 *  - ISOX_UTILS_DONE
 */
isox_utils_status_t
iso20_utils_check_authorization_req_root_path(
    const struct iso20_exiDocument *message,
    const uint8_t *challenge,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_crt_t root_cert;

    /* import the root certificate */
    rc = isox_utils_load_root_cert(root_cert_path, &root_cert);
    if (rc == ISOX_UTILS_DONE) {
        rc = iso20_utils_check_authorization_req_root_cert(message, challenge, root_cert, pubkey);
        gnutls_x509_crt_deinit(root_cert);
    }
    return rc;
}
