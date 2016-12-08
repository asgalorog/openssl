#ifndef HEADER_RW_H
#define HEADER_RW_H
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <string.h>
/*typedef struct gost_st GostPrivateKey;*/
typedef struct  GOST_KEY_PARAMS_st GOST_KEY_PARAMS;

typedef struct gost_st {
		   X509_ALGOR *algor;
	     X509_NAME *name;
		   ASN1_OCTET_STRING *private_key;
 } GostPrivateKey;

DECLARE_ASN1_FUNCTIONS(GostPrivateKey)
DECLARE_ASN1_FUNCTIONS(GOST_KEY_PARAMS)

int gpk_to_evp(EVP_PKEY * pkey, GostPrivateKey * priv);
GostPrivateKey *read_key_file(char *key_file);
int mykeygen(char *keyfile, char *keyparams, char *subject);
int check_certs(X509 *mycert,X509* oppcert);
int check_exten(X509* cert);
#endif
