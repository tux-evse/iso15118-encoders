
#include "iso-2-utils.h"

#include <stdint.h>
#include <stdbool.h>
#include <memory.h>

#define MAX_EXI_SIZE        8192
#define DIGEST_ALGO         GNUTLS_DIG_SHA256
#define DIGEST_MAX_SIZE     32
#define CHALLENGE_SIZE      16
#define SIGNING_ALGO        GNUTLS_SIGN_ECDSA_SECP256R1_SHA256

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


iso2_utils_status_t
iso2_utils_check_metering_receipt_req_signature(
	const struct iso2_V2G_Message *message,
	const uint8_t *challenge,
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
