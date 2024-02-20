#include "iso-2-utils.h"

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

unsigned fragment_digest(
    const struct iso2_exiFragment *fragment,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest
) {
    unsigned char buffer[MAX_EXI_SIZE];
    exi_bitstream_t stream;
    int rc;

    /* canonisation of the fragment */
    //memset(buffer, 0, sizeof buffer);
    //memset(&stream, 0, sizeof stream);
    exi_bitstream_init(&stream, buffer, sizeof buffer, 0, NULL);
    rc = encode_iso2_exiFragment(&stream, fragment);
    if (rc != EXI_ERROR__NO_ERROR)
        return 0;

    /* check digest length */
    rc = gnutls_hash_get_len(dalgo);
    if (rc <= 0 || (unsigned)rc > szdigest)
        return 0;

    /* compute the digest */
    rc = gnutls_hash_fast(dalgo, buffer, exi_bitstream_get_length(&stream), digest);
    if (rc != 0)
        return 0;
    return (unsigned)gnutls_hash_get_len(dalgo);
}

unsigned
signature_digest(
    const struct iso2_SignatureType *signature,
    gnutls_digest_algorithm_t dalgo,
    uint8_t *digest,
    unsigned szdigest
) {
    struct iso2_exiFragment sig;
    memset(&sig, 0, sizeof sig);
    init_iso2_exiFragment(&sig);
    sig.SignedInfo_isUsed = 1;
    memcpy(&sig.SignedInfo, &signature->SignedInfo, sizeof sig.SignedInfo);
    return fragment_digest(&sig, dalgo, digest, szdigest);
}

int sign_single_fragment(
        const char *key,
        struct iso2_MessageHeaderType *header,
        const struct iso2_exiFragment *fragment
) {
    int rc;
    unsigned dsz;
    gnutls_privkey_t privkey;
    uint8_t digest[DIGEST_MAX_SIZE];
    gnutls_datum_t data, sig;

    /* create the digest of the fragment */
    dsz = fragment_digest(
                fragment,
                DIGEST_ALGO,
                header->Signature.SignedInfo.Reference.array[0].DigestValue.bytes,
                (unsigned)sizeof header->Signature.SignedInfo.Reference.array[0].DigestValue.bytes);
    if (dsz == 0)
        return -1;
    header->Signature.SignedInfo.Reference.array[0].DigestValue.bytesLen = (uint16_t)dsz;
    header->Signature.SignedInfo.Reference.arrayLen = 1;

    /* create the digest of the digests */
    dsz = signature_digest(
                &header->Signature,
                DIGEST_ALGO,
                digest,
                (unsigned)sizeof digest);
    if (dsz == 0)
        return -1;

    /* load the private key */
    rc = load_privkey(key, &privkey);
    if (rc != 0)
        return rc;

    /* sign the digests */
    data.data = digest;
    data.size = dsz;
    sig.data = NULL;
    sig.size = 0;
    rc = gnutls_privkey_sign_hash2(privkey, SIGNING_ALGO, 0, &data, &sig);
    gnutls_privkey_deinit(privkey);
    if (rc != GNUTLS_E_SUCCESS || sig.size > sizeof header->Signature.SignatureValue.CONTENT.bytes) {
        gnutls_free(sig.data);
        return -1;
    }
    memcpy(header->Signature.SignatureValue.CONTENT.bytes, sig.data, sig.size);
    header->Signature.SignatureValue.CONTENT.bytesLen = (uint16_t)sig.size;
    header->Signature_isUsed = 1;
    gnutls_free(sig.data);

    return 0;
}

void do_test_iso2_utils_check_authorization_req_signature(const char *priv, const char *cert, int erc)
{
    int rc;
    struct iso2_V2G_Message msg;
    struct iso2_exiFragment fragment;
    gnutls_pubkey_t pubkey;

    /* forge the test message */
    memset(&msg, 0, sizeof msg);
    init_iso2_V2G_Message(&msg);
    msg.Body.AuthorizationReq_isUsed = 1;
    memcpy(msg.Body.AuthorizationReq.Id.characters, "1234", 4);
    msg.Body.AuthorizationReq.Id.charactersLen = 4;
    msg.Body.AuthorizationReq.Id_isUsed = 1;
    memcpy(msg.Body.AuthorizationReq.GenChallenge.bytes, CHALLENGE, CHALLENGE_SIZE);
    msg.Body.AuthorizationReq.GenChallenge.bytesLen = CHALLENGE_SIZE;
    msg.Body.AuthorizationReq.GenChallenge_isUsed = 1;

    /* make signature of the single fragment */
    memset(&fragment, 0, sizeof fragment);
    init_iso2_exiFragment(&fragment);
    fragment.AuthorizationReq_isUsed = 1;
    memcpy(&fragment.AuthorizationReq, &msg.Body.AuthorizationReq, sizeof fragment.AuthorizationReq);
    rc = sign_single_fragment(priv, &msg.Header, &fragment);
    if (rc == 0) {
        rc = load_pubkey_of_cert(cert, &pubkey);
        if (rc == 0) {
            rc = iso2_utils_check_authorization_req_signature(&msg, CHALLENGE, pubkey);
            gnutls_pubkey_deinit(pubkey);
        }
    }
    tap(rc == erc, "verification authorization req for %s and %s: found %d, expected %d", priv, cert, rc, erc);
}

void test_iso2_utils_check_authorization_req_signature()
{
    do_test_iso2_utils_check_authorization_req_signature("end.key.der", "end.der", 0);
    do_test_iso2_utils_check_authorization_req_signature("end2.key.der", "end.der", ISO2_UTILS_ERROR_BAD_SIGNATURE);
}

void do_test_iso2_utils_check_payment_details_req(const char *emaid, int idchain, int erc)
{
    struct iso2_V2G_Message msg;
    gnutls_pubkey_t pubkey;
    int rc;

    memset(&msg, 0, sizeof msg);
    init_iso2_V2G_Message(&msg);
    msg.Body.PaymentDetailsReq_isUsed = 1;
    msg.Body.PaymentDetailsReq.eMAID.charactersLen = (uint16_t)strlen(emaid);
    memcpy(msg.Body.PaymentDetailsReq.eMAID.characters, emaid, msg.Body.PaymentDetailsReq.eMAID.charactersLen);
    loadcertdef(chains[idchain].cert, (certdef*)&msg.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate);
    msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates_isUsed = 1;
    msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 1;
    loadcertdef(chains[idchain].sub, (certdef*)&msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0]);
    rc = iso2_utils_check_payment_details_req_root_path(&msg, chains[idchain].root, &pubkey);
    tap(rc == erc, "verification of payment details for %s, chain %d: found %d, expected %d", emaid, idchain, rc, erc);
    if (rc == 0)
        iso2_utils_drop_pubkey(&pubkey);
}

void test_iso2_utils_check_payment_details_req()
{
    do_test_iso2_utils_check_payment_details_req("", 0, ISO2_UTILS_ERROR_EMAID_MISMATCH);
    do_test_iso2_utils_check_payment_details_req("45er-tert-g65", 0, ISO2_UTILS_ERROR_EMAID_MISMATCH);
    do_test_iso2_utils_check_payment_details_req("E-M-A--ID", 0, 0);
    do_test_iso2_utils_check_payment_details_req("emaid", 0, 0);
    do_test_iso2_utils_check_payment_details_req("emaid", 1, 0);
    do_test_iso2_utils_check_payment_details_req("emaid", 2, ISO2_UTILS_ERROR_INVALID_CERT);
    do_test_iso2_utils_check_payment_details_req("emaid", 3, ISO2_UTILS_ERROR_INVALID_CERT);
}

int main(int ac, char **av)
{
    test_iso2_utils_check_payment_details_req();
    test_iso2_utils_check_authorization_req_signature();
    endtap();
    return 0;
}

