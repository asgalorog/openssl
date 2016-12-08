#ifndef HEADER_CERTGEN_H
 #define HEADER_CERTGEN_H
#include "rw_cert_and_key.h"
#include <stdio.h>
#include <openssl/x509v3.h>
int createX509(char *priv_CA_key, char *priv_subk_key, int valid, int serial,char *cert_out,int flag);
int createCAX509(char *priv_key, int valid, int serial, char *cert_out);
X509* read_cert(char *name);
#endif
