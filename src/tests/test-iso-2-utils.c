#include "iso-2-utils.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_CERT_SIZE 2000

typedef
    struct {
        uint8_t bytes[iso2_certificateType_BYTES_SIZE];
        uint16_t bytesLen;
    }
    certdef;


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


int do_test_iso2_utils_check_payement_details_req(const char *emaid)
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
    if (rc == 0)
        gnutls_pubkey_deinit(pubkey);
printf("%s: %d\n",emaid,rc);
    return rc;
}

void test_iso2_utils_check_payement_details_req()
{
    char *ems[] = { "", "45er-tert-g65", "emaid", "E-M-A--ID" };
    int im;

    for (im = 0 ; im  < (int)(sizeof ems/sizeof*ems) ; im++)
        do_test_iso2_utils_check_payement_details_req(ems[im]);
}

int main(int ac, char **av)
{
    test_iso2_utils_check_payement_details_req();
    return 0;
}