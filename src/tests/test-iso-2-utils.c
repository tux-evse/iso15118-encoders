#include "iso-2-utils.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#define MAX_CERT_SIZE 2000

typedef
    struct {
        uint8_t bytes[iso2_certificateType_BYTES_SIZE];
        uint16_t bytesLen;
    }
    certdef;

int ntap = 0;
void endtap()
{
    printf("1..%d\n", ntap);
}
void tap(int sts, const char *fmt, ...)
{
    va_list ap;
    printf("%s %d - ", sts ? "ok" : "not ok", ++ntap);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    putchar('\n');
    va_end(ap);
}

int itap = 0;

size_t
loadcertin(
    const char *path,
    uint8_t *buffer,
    size_t size
) {
    int fd, rc;
    ssize_t rsz;

    /* read the file */
    fd = open(path, O_RDONLY);
    if (fd < 0)
	    return 0;
    rsz = read(fd, buffer, size);
    close(fd);
    if (rsz < 0)
	    return 0;
    if ((size_t)rsz >= size)
	    return 0;
    return (size_t)rsz;
}


int
loadcert(
    const char *path,
    gnutls_x509_crt_t *cert
) {
    int rc;
    gnutls_datum_t data;
    uint8_t buffer[MAX_CERT_SIZE];
    size_t size = loadcertin(path, buffer, sizeof buffer);
    if (size == 0)
	    return -1;

    /* make the certificate */
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

int loadcertdef(
    const char *path,
    certdef *cdef
) {
    size_t size = loadcertin(path, cdef->bytes, sizeof cdef->bytes);
    if (size == 0)
        return -1;
    cdef->bytesLen = (uint16_t)size;
    return 0;
}


void do_test_iso2_utils_check_payement_details_req(const char *emaid, int erc)
{
    struct iso2_V2G_Message msg;
    gnutls_pubkey_t pubkey;
    int rc;

    memset(&msg, 0, sizeof msg);
    init_iso2_V2G_Message(&msg);
    msg.Body.PaymentDetailsReq_isUsed = 1;
    msg.Body.PaymentDetailsReq.eMAID.charactersLen = (uint16_t)strlen(emaid);
    memcpy(msg.Body.PaymentDetailsReq.eMAID.characters, emaid, msg.Body.PaymentDetailsReq.eMAID.charactersLen);
    loadcertdef("end.der", (certdef*)&msg.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate);
    msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates_isUsed = 1;
    msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 1;
    loadcertdef("sub.der", (certdef*)&msg.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0]);
    rc = iso2_utils_check_payement_details_req(&msg, "root.der", &pubkey);
    tap(rc == erc, "verification of payment details for %s: found %d, expected %d", emaid, rc, erc);
    if (rc == 0)
        iso2_utils_drop_pubkey(&pubkey);
}

void test_iso2_utils_check_payement_details_req()
{
    do_test_iso2_utils_check_payement_details_req("", ISO2_UTILS_ERROR_EMAID_MISMATCH);
    do_test_iso2_utils_check_payement_details_req("45er-tert-g65", ISO2_UTILS_ERROR_EMAID_MISMATCH);
    do_test_iso2_utils_check_payement_details_req("emaid", 0);
    do_test_iso2_utils_check_payement_details_req("E-M-A--ID", 0);
}

int main(int ac, char **av)
{
    test_iso2_utils_check_payement_details_req();
    endtap();
   return 0;
}