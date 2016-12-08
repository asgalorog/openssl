#include "gencert.h"

int X509exten(X509 * mycert, char *data, int NID)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, mycert, mycert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, NID, data);
	if (!ex){
		 printf("unknown ext!\n");
		return 0;
	}
	X509_add_ext(mycert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

X509 *read_cert(char *name)
{
	X509 *cert = NULL;
	FILE *fk = fopen(name, "rb");
	if (fk == NULL) {
		printf("Не существует файла с таким именем %s\n",name);
		return NULL;
	}
	unsigned int length = 0;
	unsigned int fptr = ftell(fk);
	fseek(fk, 0, SEEK_END);
	length = ftell(fk) - fptr;
	fclose(fk);
	unsigned char *buff = (char *)malloc(length);
	BIO *inkey = NULL;
	inkey = BIO_new_file(name, "r");
	BIO_read(inkey, buff, length);
	BIO_free(inkey);
	const unsigned char *buf2 = buff;
	if (!d2i_X509(&cert, &buf2, length))
		printf("Указанный файл %s не содержит X509 сертификат\n",name);
	free(buff);
	return cert;

}

int createX509(char *priv_CA_key, char *priv_subk_key, int valid, int serial,
		char *cert_out, int flag)
{
	GostPrivateKey *GCAkey = NULL;
	GostPrivateKey *Gsubjkey = NULL;
	GCAkey = read_key_file(priv_CA_key);
	if(GCAkey == NULL)
	{
		return -1;
	}
	Gsubjkey = read_key_file(priv_subk_key);
	if(Gsubjkey == NULL)
	{
		GostPrivateKey_free(GCAkey);
		return -1;
	}
	EVP_PKEY *CAkey = EVP_PKEY_new();
	EVP_PKEY *subkey = EVP_PKEY_new();
	if(!gpk_to_evp(CAkey, GCAkey) || !gpk_to_evp(subkey, Gsubjkey))
	{
		EVP_PKEY_free(CAkey);
		EVP_PKEY_free(subkey);
		GostPrivateKey_free(GCAkey);
		 GostPrivateKey_free(Gsubjkey);
		return -1;
	}
	X509 *subcert = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(subcert), serial);
	X509_gmtime_adj(X509_get_notBefore(subcert), 0);
	X509_gmtime_adj(X509_get_notAfter(subcert), valid * 24 * 60 * 60);
	X509_set_issuer_name(subcert, GCAkey->name);
	X509_set_subject_name(subcert, Gsubjkey->name);
	if (flag) {
		X509exten(subcert, "CA:TRUE", NID_basic_constraints);
		X509exten(subcert,
			  "keyCertSign,cRLSign,nonRepudiation,keyEncipherment,keyAgreement,digitalSignature",
			  NID_key_usage);
	} else
		X509exten(subcert,
			  "nonRepudiation,keyEncipherment,keyAgreement,digitalSignature",
			  NID_key_usage);
	X509_set_pubkey(subcert, subkey);
	X509_set_version(subcert,2);
	X509_sign(subcert, CAkey, NULL);
	unsigned char *buff = NULL;
	int cert_length = i2d_X509(subcert, &buff);
	BIO *outcert = NULL;
	int ok=0;
	outcert = BIO_new_file(cert_out, "w");
	if(outcert==NULL)
	{
		printf("Невозможно сохранить сертификат с таким именем(ошибка директории)\n");
		ok=-1;
		goto err;
	}
	BIO_write(outcert, buff, cert_length);
	BIO_free(outcert);
err:
	GostPrivateKey_free(GCAkey);
	GostPrivateKey_free(Gsubjkey);
	EVP_PKEY_free(subkey);
	EVP_PKEY_free(CAkey);
	free(buff);
	X509_free(subcert);
	return ok;
}

int createCAX509(char *priv_key, int valid, int serial, char *cert_out)
{
	GostPrivateKey *mykey = NULL;
	mykey = read_key_file(priv_key);
	if(mykey==NULL)
		return -1;
	EVP_PKEY *key = EVP_PKEY_new();
	if(!gpk_to_evp(key, mykey)){
		GostPrivateKey_free(mykey);
		EVP_PKEY_free(key);
		return -1;
	}
	X509 *mycert = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(mycert), serial);
	X509_gmtime_adj(X509_get_notBefore(mycert), 0);
	X509_gmtime_adj(X509_get_notAfter(mycert), valid * 24 * 60 * 60);
	X509_set_issuer_name(mycert, mykey->name);
	X509_set_subject_name(mycert, mykey->name);
	X509exten(mycert, "CA:TRUE", NID_basic_constraints);
	X509exten(mycert,
		  "digitalSignature,keyCertSign,cRLSign,nonRepudiation,keyEncipherment,keyAgreement",
		  NID_key_usage);
	X509_set_pubkey(mycert, key);
	X509_set_version(mycert,2); 
	X509_sign(mycert, key, NULL);
	unsigned char *buff = NULL;
	int cert_length = i2d_X509(mycert, &buff);
	BIO *outcert = NULL;
	int ok=0;
	outcert = BIO_new_file(cert_out, "w");
	if(outcert==NULL)
	{
		printf("Невозможно сохранить сертификат с таким именем(ошибка директории)\n");                            
    ok=-1;
    goto err;
	}
	BIO_write(outcert, buff, cert_length);
	BIO_free(outcert);
err:
	EVP_PKEY_free(key);
	GostPrivateKey_free(mykey);
	X509_free(mycert);
	free(buff);
	return ok;
}
