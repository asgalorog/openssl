#ifndef HEADER_MYCMS_H
#define HEADER_MYCMS_H
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/cms.h>
#define PSM_COMMAND_HELLO 0
#define PSM_COMMAND_GOODBYE 1
#define PSM_COMMAND_ACK 2

typedef struct PSMText {
	STACK_OF(ASN1_UTF8STRING) *text;
}PSMText;

typedef struct PSMCommand {
	ASN1_ENUMERATED *command;
	ASN1_INTEGER *refseqno;
	ASN1_UTF8STRING * text;
} PSMCommand;

typedef struct PSMFile {
	ASN1_UTF8STRING *name;
	ASN1_OCTET_STRING *file;
}PSMFile;

typedef struct PSEC_MESSAGE {
  ASN1_OBJECT *mtype;
  union {
    PSMCommand *psmcomm;
    PSMFile *file;
		PSMText *text;
    void *other;
  } d;
  ASN1_INTEGER *seqno;
}PSEC_MESSAGE;

DECLARE_ASN1_FUNCTIONS(PSEC_MESSAGE)
DECLARE_ASN1_ITEM(PSMCommand)
DECLARE_ASN1_ITEM(PSMFile)
DECLARE_ASN1_ITEM(PSMText)

int tcp_ctrl(X509_STORE * store, char *f_mykey, char *f_mycert, char *f_oppcert,
	       int flag,char* ipport);
BIO* read2cms(X509* mycert,X509* oppcert,EVP_PKEY* mykey,X509_STORE *store,unsigned char* data,unsigned char length);
int create_cms(BIO *data,X509* mycert,X509* oppcert,EVP_PKEY *my_key,unsigned char** buff,unsigned int *length);
BIO* PSM_start(int nid_comm,unsigned char* text,char* name,int seqno,int command,int refseqno);
unsigned char* cms_decode(BIO* data,int* cntrl,int* refseqno);
BIO* read2_cms(X509* oppcert,X509* mycert,EVP_PKEY* oppkey,X509_STORE* store,unsigned char* data,unsigned int length);
#endif

