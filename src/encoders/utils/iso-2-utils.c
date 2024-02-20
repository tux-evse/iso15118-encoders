
#include "iso-2-utils.h"

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
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_get_fragment_digest(
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
    exi_bitstream_init(&stream, buffer, sizeof buffer, 0, NULL);
    rc = encode_iso2_exiFragment(&stream, fragment);
    if (rc != EXI_ERROR__NO_ERROR)
        return ISO2_UTILS_ERROR_ENCODING;

    /* check digest length */
    rc = gnutls_hash_get_len(dalgo);
    if (rc < 0 || (unsigned)rc > szdigest)
        return ISO2_UTILS_ERROR_INTERNAL1;
    *dlen = (unsigned)rc;

    /* compute the digest */
    rc = gnutls_hash_fast(dalgo, buffer, exi_bitstream_get_length(&stream), digest);
    if (rc != 0)
        return ISO2_UTILS_ERROR_MAKE_DIGEST;
    return ISO2_UTILS_DONE;
}

/**
 * Compute the hash of the info items of the signature
 * That hash is the data that is then signed.
 * Store the result in digest that is of size szdigest
 * The length of the computed hash is stored in *dlen
 * Returned status is one of:
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_get_signature_digest(
    const struct iso2_SignatureType *signature,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest,
    unsigned *dlen
) {
    struct iso2_exiFragment sig;

    /* create the digest of the signed info of the signature */
    init_iso2_exiFragment(&sig);
    sig.SignedInfo_isUsed = 1;
    memcpy(&sig.SignedInfo, &signature->SignedInfo, sizeof sig.SignedInfo);
    return iso2_utils_get_fragment_digest(&sig, dalgo, digest, szdigest, dlen);
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
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_ERROR_DIGEST_LENGTH
 *  - ISO2_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_fragment_digest(
    const struct iso2_ReferenceType *reference,
    const struct iso2_exiFragment *fragment
) {
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];

    /* get the digest of the fragment */
    int rc = iso2_utils_get_fragment_digest(fragment, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != ISO2_UTILS_DONE)
        return rc;

    /* compare with reference */
    if ((unsigned)reference->DigestValue.bytesLen != dlen)
        return ISO2_UTILS_ERROR_DIGEST_LENGTH;
    if (memcmp(digest, reference->DigestValue.bytes, dlen) != 0)
        return ISO2_UTILS_ERROR_DIGEST_MISMATCH;

    return ISO2_UTILS_DONE;
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
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_ERROR_BAD_SIGNATURE
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_signature(
    const struct iso2_SignatureType *signature,
    gnutls_pubkey_t pubkey
) {
    int rc;
    unsigned dlen;
    uint8_t digest[DIGEST_MAX_SIZE];
    gnutls_datum_t hash, sign;

    /* create the digest of the signed info of the signature */
    rc = iso2_utils_get_signature_digest(signature, DIGEST_ALGO, digest, sizeof digest, &dlen);
    if (rc != ISO2_UTILS_DONE)
        return rc;

    /* verify the signature  */
    hash.data = digest;
    hash.size = dlen;
    sign.data = (void*)signature->SignatureValue.CONTENT.bytes;
    sign.size = signature->SignatureValue.CONTENT.bytesLen;
    rc = gnutls_pubkey_verify_hash2(pubkey, SIGNING_ALGO, 0, &hash, &sign);
    if (rc < 0)
        return ISO2_UTILS_ERROR_BAD_SIGNATURE;
    return ISO2_UTILS_DONE;
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
 *  - ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_ERROR_BAD_SIGNATURE
 *  - ISO2_UTILS_ERROR_DIGEST_LENGTH
 *  - ISO2_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_single_fragment_signature(
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
    return ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED;

    /* check validity of fragment's hash */
    rc = iso2_utils_check_fragment_digest(&signature->SignedInfo.Reference.array[0], fragment);
    if (rc != ISO2_UTILS_DONE)
        return rc;

    /* check validity of signed info */
    return iso2_utils_check_signature(signature, pubkey);
}

/**
 * Checks that the AuthorisationReq message has a challenge signed
 * by the given key
 *
 * Returned status is one of:
 *  - ISO2_UTILS_ERROR_NOT_AUTHORIZATION_REQ
 *  - ISO2_UTILS_ERROR_NO_SIGNATURE
 *  - ISO2_UTILS_ERROR_NO_CHALLENGE
 *  - ISO2_UTILS_ERROR_CHALLENGE_SIZE
 *  - ISO2_UTILS_ERROR_CHALLENGE_MISMATCH
 *  - ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_ERROR_BAD_SIGNATURE
 *  - ISO2_UTILS_ERROR_DIGEST_LENGTH
 *  - ISO2_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_authorization_req_signature(
    const struct iso2_V2G_Message *message,
    const uint8_t *challenge,
    gnutls_pubkey_t pubkey
) {
    struct iso2_exiFragment fragment;

    /* validate the request */
    if (message->Body.AuthorizationReq_isUsed == 0)
        return ISO2_UTILS_ERROR_NOT_AUTHORIZATION_REQ;
    if (message->Header.Signature_isUsed == 0)
        return ISO2_UTILS_ERROR_NO_SIGNATURE;

    /* validate the challenge */
    if (message->Body.AuthorizationReq.GenChallenge_isUsed == 0)
        return ISO2_UTILS_ERROR_NO_CHALLENGE;
    if (message->Body.AuthorizationReq.GenChallenge.bytesLen != CHALLENGE_SIZE)
        return ISO2_UTILS_ERROR_CHALLENGE_SIZE;
    if (memcmp(message->Body.AuthorizationReq.GenChallenge.bytes, challenge, CHALLENGE_SIZE))
        return ISO2_UTILS_ERROR_CHALLENGE_MISMATCH;

    /* initiate the fragment to check */
    init_iso2_exiFragment(&fragment);
    fragment.AuthorizationReq_isUsed = 1u;
    memcpy(&fragment.AuthorizationReq, &message->Body.AuthorizationReq, sizeof fragment.AuthorizationReq);

    /* check the fragment */
    return iso2_utils_check_single_fragment_signature(&message->Header.Signature, &fragment, pubkey);
}

/**
 * Checks that the MeteringReceiptReq message is signed
 * by the given key
 *
 * Returned status is one of:
 *  - ISO2_UTILS_ERROR_NOT_METERING_RECEIPT_REQ
 *  - ISO2_UTILS_ERROR_NO_SIGNATURE
 *  - ISO2_UTILS_ERROR_NOT_SINGLE_SIGNED
 *  - ISO2_UTILS_ERROR_ENCODING
 *  - ISO2_UTILS_ERROR_INTERNAL1
 *  - ISO2_UTILS_ERROR_BAD_SIGNATURE
 *  - ISO2_UTILS_ERROR_DIGEST_LENGTH
 *  - ISO2_UTILS_ERROR_DIGEST_MISMATCH
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_metering_receipt_req_signature(
    const struct iso2_V2G_Message *message,
    gnutls_pubkey_t pubkey
) {
    struct iso2_exiFragment fragment;

    /* validate the request */
    if (message->Body.MeteringReceiptReq_isUsed == 0)
        return ISO2_UTILS_ERROR_NOT_METERING_RECEIPT_REQ;
    if (message->Header.Signature_isUsed == 0)
        return ISO2_UTILS_ERROR_NO_SIGNATURE;

    /* initiate the fragment to check */
    init_iso2_exiFragment(&fragment);
    fragment.MeteringReceiptReq_isUsed = 1u;
    memcpy(&fragment.MeteringReceiptReq, &message->Body.MeteringReceiptReq, sizeof fragment.MeteringReceiptReq);

    /* check the fragment */
    return iso2_utils_check_single_fragment_signature(&message->Header.Signature, &fragment, pubkey);
}

/**
 * Loads the certificate at the given path in cert
 *
 * Returned status is one of:
 *  - ISO2_UTILS_ERROR_ROOTCERT_OPEN
 *  - ISO2_UTILS_ERROR_ROOTCERT_READ
 *  - ISO2_UTILS_ERROR_ROOTCERT_OVERFLOW
 *  - ISO2_UTILS_ERROR_INTERNAL5
 *  - ISO2_UTILS_ERROR_ROOTCERT_IMPORT
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
load_root_cert(
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
	    return ISO2_UTILS_ERROR_ROOTCERT_OPEN;
    rsz = read(fd, buffer, sizeof buffer);
    close(fd);
    if (rsz < 0)
        return ISO2_UTILS_ERROR_ROOTCERT_READ;
    if ((size_t)rsz > MAX_CERT_SIZE)
        return ISO2_UTILS_ERROR_ROOTCERT_OVERFLOW;

    /* make the certificate */
    rc = gnutls_x509_crt_init(cert);
    if (rc != GNUTLS_E_SUCCESS) {
        return ISO2_UTILS_ERROR_INTERNAL5;
    }
    data.data = buffer;
    data.size = (size_t)rsz;
    rc = gnutls_x509_crt_import(*cert, &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        gnutls_x509_crt_deinit(*cert);
        return ISO2_UTILS_ERROR_ROOTCERT_IMPORT;
    }
    return ISO2_UTILS_DONE;
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
 *  - ISO2_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_SUBJECT_CN
 *  - ISO2_UTILS_ERROR_EMAID_MISMATCH
 *  - ISO2_UTILS_ERROR_TOO_MANY_CERT
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_INVALID_CERT
 *  - ISO2_UTILS_ERROR_INTERNAL2
 *  - ISO2_UTILS_ERROR_INTERNAL3
 *  - ISO2_UTILS_ERROR_INTERNAL7
 *  - ISO2_UTILS_ERROR_INTERNAL8
 *  - ISO2_UTILS_ERROR_INTERNAL9;
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_payment_details_req_trust_list(
    const struct iso2_V2G_Message *message,
    gnutls_x509_trust_list_t trust_list,
    gnutls_pubkey_t *pubkey
) {
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
        return ISO2_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ;
    msgreq = &message->Body.PaymentDetailsReq;
    msgcert = &msgreq->ContractSignatureCertChain;

    /* import the certificate */
    rc = gnutls_x509_crt_init(&certs[0]);
    if (rc != GNUTLS_E_SUCCESS)
        return ISO2_UTILS_ERROR_INTERNAL2;
    ncerts = 1;
    data.data = (void*)msgcert->Certificate.bytes;
    data.size = msgcert->Certificate.bytesLen;
    rc = gnutls_x509_crt_import(certs[0], &data, GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        rc = ISO2_UTILS_ERROR_CERT_IMPORT;
        goto cleanup;
    }

    /* validate the MEAN */
    emaidsz = sizeof emaid;
    rc = gnutls_x509_crt_get_dn_by_oid(certs[0], GNUTLS_OID_X520_COMMON_NAME, 0, 0, emaid, &emaidsz);
    if (rc < 0) {
        rc = ISO2_UTILS_ERROR_SUBJECT_CN;
        goto cleanup;
    }
    len = compare_emaid(emaid, (unsigned) emaidsz, msgreq->eMAID.characters, (unsigned)msgreq->eMAID.charactersLen);
    if (len == 0)  {
        rc = ISO2_UTILS_ERROR_EMAID_MISMATCH;
        goto cleanup;
    }

    /* import the sub certificates */
    cnt = msgcert->SubCertificates_isUsed ? msgcert->SubCertificates.Certificate.arrayLen : 0;
    if (cnt > MAX_NR_SUB_CERT) {
        rc = ISO2_UTILS_ERROR_TOO_MANY_CERT;
        goto cleanup;
    }
    for (idx = 0 ; idx < cnt ; idx++) {
        rc = gnutls_x509_crt_init(&certs[ncerts]);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = ISO2_UTILS_ERROR_INTERNAL3;
            goto cleanup;
        }
        data.data = (void*)msgcert->SubCertificates.Certificate.array[idx].bytes;
        data.size = msgcert->SubCertificates.Certificate.array[idx].bytesLen;
        rc = gnutls_x509_crt_import(certs[ncerts++], &data, GNUTLS_X509_FMT_DER);
        if (rc != GNUTLS_E_SUCCESS) {
            rc = ISO2_UTILS_ERROR_CERT_IMPORT;
            goto cleanup;
        }
    }

    /* check the trust chain */
    vsts = 0;
    rc = gnutls_x509_trust_list_verify_crt(trust_list, certs, ncerts, 0, &vsts, NULL);
    if (rc != GNUTLS_E_SUCCESS)
            rc = ISO2_UTILS_ERROR_INTERNAL7;
    else if (vsts & GNUTLS_CERT_INVALID)
            rc = ISO2_UTILS_ERROR_INVALID_CERT;
    else
            rc = ISO2_UTILS_DONE;
    if (rc != ISO2_UTILS_DONE)
        goto cleanup;

    /* extract the public key */
    if (pubkey != NULL) {
        rc = gnutls_pubkey_init(pubkey);
        if (rc != GNUTLS_E_SUCCESS)
            rc = ISO2_UTILS_ERROR_INTERNAL8;
        else {
            rc = gnutls_pubkey_import_x509(*pubkey, certs[0], 0);
            if (rc == GNUTLS_E_SUCCESS)
                rc = ISO2_UTILS_DONE;
            else {
                gnutls_pubkey_deinit(*pubkey);
                rc = ISO2_UTILS_ERROR_INTERNAL9;
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
 *  - ISO2_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_SUBJECT_CN
 *  - ISO2_UTILS_ERROR_EMAID_MISMATCH
 *  - ISO2_UTILS_ERROR_TOO_MANY_CERT
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_INVALID_CERT
 *  - ISO2_UTILS_ERROR_INTERNAL2
 *  - ISO2_UTILS_ERROR_INTERNAL3
 *  - ISO2_UTILS_ERROR_INTERNAL4
 *  - ISO2_UTILS_ERROR_INTERNAL6
 *  - ISO2_UTILS_ERROR_INTERNAL7
 *  - ISO2_UTILS_ERROR_INTERNAL8
 *  - ISO2_UTILS_ERROR_INTERNAL9;
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_payment_details_req_root_cert(
    const struct iso2_V2G_Message *message,
    gnutls_x509_crt_t root_cert,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_trust_list_t trust_list;

    /* initiate the trust list */
    rc = gnutls_x509_trust_list_init(&trust_list, 1);
    if (rc != GNUTLS_E_SUCCESS)
        return ISO2_UTILS_ERROR_INTERNAL4;
    rc = gnutls_x509_trust_list_add_cas(trust_list, &root_cert, 1, 0);
    if (rc != 1)
        rc = ISO2_UTILS_ERROR_INTERNAL6;
    else
        /* check the trust list */
        rc = iso2_utils_check_payment_details_req_trust_list(message, trust_list, pubkey);
    gnutls_x509_trust_list_deinit(trust_list, 0);
    return rc;
}

/**
 * Check the PaymentDetailsReq in its consistency, its link to the
 * authority if root_cert_path != NULL and extracts the public key
 * if pubkey it not NULL
 *
 * Returned status is one of:
 *  - ISO2_UTILS_ERROR_NOT_PAYEMENT_DETAIL_REQ
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_SUBJECT_CN
 *  - ISO2_UTILS_ERROR_EMAID_MISMATCH
 *  - ISO2_UTILS_ERROR_TOO_MANY_CERT
 *  - ISO2_UTILS_ERROR_CERT_IMPORT
 *  - ISO2_UTILS_ERROR_INVALID_CERT
 *  - ISO2_UTILS_ERROR_ROOTCERT_OPEN
 *  - ISO2_UTILS_ERROR_ROOTCERT_READ
 *  - ISO2_UTILS_ERROR_ROOTCERT_OVERFLOW
 *  - ISO2_UTILS_ERROR_ROOTCERT_IMPORT
 *  - ISO2_UTILS_ERROR_INTERNAL2
 *  - ISO2_UTILS_ERROR_INTERNAL3
 *  - ISO2_UTILS_ERROR_INTERNAL4
 *  - ISO2_UTILS_ERROR_INTERNAL5
 *  - ISO2_UTILS_ERROR_INTERNAL6
 *  - ISO2_UTILS_ERROR_INTERNAL7
 *  - ISO2_UTILS_ERROR_INTERNAL8
 *  - ISO2_UTILS_ERROR_INTERNAL9;
 *  - ISO2_UTILS_DONE
 */
iso2_utils_status_t
iso2_utils_check_payment_details_req_root_path(
    const struct iso2_V2G_Message *message,
    const char *root_cert_path,
    gnutls_pubkey_t *pubkey
) {
    int rc;
    gnutls_x509_crt_t root_cert;

    /* import the root certificate */
    rc = load_root_cert(root_cert_path, &root_cert);
    if (rc == ISO2_UTILS_DONE) {
        rc = iso2_utils_check_payment_details_req_root_cert(message, root_cert, pubkey);
        gnutls_x509_crt_deinit(root_cert);
    }
    return rc;
}

/**
 * Remove memory used by the pubkey
 */
void
iso2_utils_drop_pubkey(
    gnutls_pubkey_t *pubkey
) {
    gnutls_pubkey_deinit(*pubkey);
}
