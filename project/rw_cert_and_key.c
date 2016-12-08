#include <openssl/x509_vfy.h>
#include "rw_cert_and_key.h"
#include "keyparams.h"
#include <openssl/x509.h>
/*************************************************/
//ASN1 структуры для хранилища ключа и параметров ключа

ASN1_SEQUENCE(GostPrivateKey) = {
	ASN1_SIMPLE(GostPrivateKey, algor, X509_ALGOR),
	    ASN1_SIMPLE(GostPrivateKey, name, X509_NAME),
	    ASN1_SIMPLE(GostPrivateKey, private_key, ASN1_OCTET_STRING)
}

ASN1_SEQUENCE_END(GostPrivateKey)

    IMPLEMENT_ASN1_FUNCTIONS(GostPrivateKey)

struct GOST_KEY_PARAMS_st {
	ASN1_OBJECT *key_params;
	ASN1_OBJECT *hash_params;
};

ASN1_SEQUENCE(GOST_KEY_PARAMS) =
{
	ASN1_SIMPLE(GOST_KEY_PARAMS, key_params, ASN1_OBJECT),
	    ASN1_SIMPLE(GOST_KEY_PARAMS, hash_params, ASN1_OBJECT)
} ASN1_SEQUENCE_END(GOST_KEY_PARAMS)

    IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_PARAMS)
/*****************************************************/
int fill_GOST2001_param(EC_KEY * ec, int nid);

/*****************************************************/
//запись набора криптопараметров в ASN1_STRING

ASN1_STRING *gost_param(int param_nid)
{
	ASN1_STRING *params = ASN1_STRING_new();
	GOST_KEY_PARAMS *gkp = GOST_KEY_PARAMS_new();
	gkp->key_params = OBJ_nid2obj(param_nid);
	gkp->hash_params = OBJ_nid2obj(NID_id_GostR3411_94_CryptoProParamSet);
	params->length = i2d_GOST_KEY_PARAMS(gkp, &params->data);
	params->type = V_ASN1_SEQUENCE;
	GOST_KEY_PARAMS_free(gkp);
	return params;
}

void gost_2001_gen_pub(EC_KEY * ec);

int parse_subject(char *s, GostPrivateKey * pkey);

/****************************************************/
//преобразование GostPrivateKey в EVP_PKEY

int gpk_to_evp(EVP_PKEY * pkey, GostPrivateKey * priv)
{
	if(pkey==NULL)
	{
		printf("В функцию gkp_to_evp был передан NULL!Критическая ошибка\n");
		return 0;
	}
	GOST_KEY_PARAMS *gkp = NULL;
	ASN1_OBJECT *palg_obj = NULL;
	int ptype = V_ASN1_UNDEF;
	int param_nid = NID_undef;
	void *_pval;
	ASN1_STRING *pval = NULL;
	const unsigned char *buff;
	X509_ALGOR_get0(&palg_obj, &ptype, &_pval, priv->algor);
	pval = _pval;
	buff = pval->data;
	gkp = d2i_GOST_KEY_PARAMS(NULL, &buff, pval->length);
	if (!gkp){//проверяем правильность декодирования GKP
		printf("Проблема с декодированием параметров ключа(GKP) при декодировании ключа!Критическая ошибка!\n");
		return 0;
	}
	param_nid = OBJ_obj2nid(gkp->key_params);
	if(param_nid==NID_undef)//тут саму GKP,гарантируем что nid есть.
	{
		 GOST_KEY_PARAMS_free(gkp);
		printf("Параметры ключа не были определены!Критическая ошибка!\n");
		return 0;
	}
	EVP_PKEY_set_type(pkey, NID_id_GostR3410_2001);
	EC_KEY *	ec = EC_KEY_new();
	EVP_PKEY_assign(pkey, NID_id_GostR3410_2001, ec);//не может быть ошибки.Т.к. engine уже корретный(проверен ранее), выше проверены параметры
	if(!fill_GOST2001_param(ec, param_nid)){
		GOST_KEY_PARAMS_free(gkp);
		return 0;
	}
	if(ASN1_STRING_length(priv->private_key)==0)
	{
		 GOST_KEY_PARAMS_free(gkp);
		printf("в хранилище не оказалось закрытого ключа!Критическая ошибка!\n");
		return 0;
	}
	const unsigned char *priv_key = ASN1_STRING_data(priv->private_key);
	int length = ASN1_STRING_length(priv->private_key);
	BIGNUM *priv_BN = NULL;
	priv_BN = BN_bin2bn(priv_key, length, NULL);
	EC_KEY_set_private_key(ec, (const BIGNUM *)priv_BN);
	gost_2001_gen_pub(ec);
	BN_free(priv_BN);
	GOST_KEY_PARAMS_free(gkp);
	return 1;
}

/******************************************************/
//установка параметров для генерации открытого ключа

int fill_GOST2001_param(EC_KEY * ec, int nid)
{
	EC_GROUP *grp = NULL;
	R3410_2001_params *params = R3410_2001_paramset;
	BIGNUM *p = NULL, *q = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
	EC_POINT *P = NULL;
	int ok=1;
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	size_t maxsize=sizeof(R3410_2001_paramset)/sizeof(R3410_2001_paramset[0]),i=0;
	while (params->nid != nid){
		i++;
		if(i==maxsize)
			{
				ok=0;
				goto err;
			}
		params++;

	}
	BN_hex2bn(&p, params->p);
	BN_hex2bn(&a, params->a);
	BN_hex2bn(&b, params->b);
	grp = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	P = EC_POINT_new(grp);
	BN_hex2bn(&x, params->x);
	BN_hex2bn(&y, params->y);
	EC_POINT_set_affine_coordinates_GFp(grp, P, x, y, ctx);
	BN_hex2bn(&q, params->q);
	EC_GROUP_set_generator(grp, P, q, NULL);
	EC_GROUP_set_curve_name(grp, params->nid);
	if (!EC_KEY_set_group(ec, grp))//ума не приложу как может до такого дойти, но вот на всякий случай
	{

		printf("Криптопараметры ключа неккоректны, эллиптическая кривая не была восстановлена!Критическая ошибка!\n");
		ok=0;
	}
err:
	EC_POINT_free(P);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_GROUP_free(grp);
	return ok;
}

/**********************************************/
//генерация открытого ключа gost2001
void gost_2001_gen_pub(EC_KEY * ec)
{
	const EC_GROUP *group = EC_KEY_get0_group(ec);//
	EC_POINT *pub_key = NULL;
	const BIGNUM *priv_key = NULL;
	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	priv_key = EC_KEY_get0_private_key(ec);
	pub_key = EC_POINT_new(group);
	EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx);
	EC_KEY_set_public_key(ec, pub_key);
	EC_POINT_free(pub_key);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
}

/************************************************/
//заполнение полей algor и pivate_key в структуре GostPrivateKey
int decode_key_and_params(EVP_PKEY * key, GostPrivateKey * pkey)
{
	int param_nid = NID_undef;
	ASN1_STRING *params = NULL;
	param_nid =
	    EC_GROUP_get_curve_name(EC_KEY_get0_group
				    (EVP_PKEY_get0((EVP_PKEY *) key)));
	params = gost_param(param_nid);
	X509_ALGOR_set0
	    (pkey->algor, OBJ_nid2obj(NID_id_GostR3410_2001), V_ASN1_SEQUENCE,
	     params);
	EC_KEY *ec = EVP_PKEY_get0(key);
	const BIGNUM *priv_BN_key = EC_KEY_get0_private_key(ec);
	int length_key = BN_num_bytes(priv_BN_key);
	char *binkey = (char *)malloc(length_key);
	BN_bn2bin(priv_BN_key, binkey);
	ASN1_OCTET_STRING_set(pkey->private_key, binkey, length_key);
	free(binkey);
	return 0;
}

/*************************************************/
//заполнение,кодирование и  запись GostPrivateKey
int key_params_and_name(char *subjname, EVP_PKEY * key, char *outfile) 
{
	int ok=0;
	GostPrivateKey *pkey = GostPrivateKey_new();
	unsigned char *buff = NULL;
	BIO* outkey=NULL;
	decode_key_and_params(key, pkey);
	ok=parse_subject(subjname, pkey);
	if(ok){
		printf("Ни один из указанных полей в --subject не является корректным.\n");
		goto err;
	}
	int length2 = i2d_GostPrivateKey(pkey, &buff);
	outkey=BIO_new_file(outfile, "w");
	if(outkey==NULL){
		printf("Путь сохранения файла некорректен\n");
		ok=-1;
		goto err;
	}
	if (buff == NULL){
		printf("problem with writing!");
		ok=-1;
		goto err;
	}
	BIO_write(outkey, buff, length2);
err:
	if(outkey!=NULL)
		BIO_free(outkey);
	if(buff!=NULL)
		free(buff);
	GostPrivateKey_free(pkey);
	return ok;
}

/***********************************************/
//Чтение и декодирование GostPrivateKey
GostPrivateKey *read_key_file(char *key_file)
{
	GostPrivateKey *pkey = NULL;
	FILE *fk = fopen(key_file, "rb");
	if(fk==NULL)
	{
		printf("отсутвует файл ключа с таким именем:%s\n",key_file);
		return NULL;
	}
	unsigned int length = 0;
	unsigned int fptr = ftell(fk);
	fseek(fk, 0, SEEK_END);
	length = ftell(fk) - fptr;
	fclose(fk);
	unsigned char *buff = (char *)malloc(length);
	BIO *inkey = NULL;
	inkey = BIO_new_file(key_file, "r");
	BIO_read(inkey, buff, length);
	BIO_free(inkey);
	const unsigned char *buf2 = buff;
	if (!d2i_GostPrivateKey(&pkey, &buf2, length)){
		printf("Указанный файл %s не содержит закрытый ключ!\n",key_file);
	GostPrivateKey_free(pkey);
	}
	free(buff);
	return pkey;
}

/********************************************/
//первоначальная генерация ключевой пары GOST2001
int mykeygen(char *keyfile, char *keyparams, char *subject)
{

	ENGINE *e = NULL;
	e = ENGINE_by_id("gost");
	int t=0;
	if (e == NULL) {
		printf("problem with engine\n");
		t=-1;
		goto err;
	}
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2001, e);
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_CTX_ctrl_str(ctx, "paramset", keyparams);
	EVP_PKEY_keygen(ctx, &key);
	EVP_PKEY_CTX_free(ctx);
	if (key == NULL) {
		printf("Проверьте параметры ключа!\n");
		t=-1;
		goto err;
	}
	t=key_params_and_name(subject, key, keyfile);
err:
	EVP_PKEY_free(key);
	ENGINE_free(e);
	if(t==-1)
		return 0;
	return 1;
}

/*********************************************/
//парсниг X509_name из argv и заполнение поля name в GostPrivateKey
int param_number(char *s)
{
	int k = 0, i = 0;
	char *st = s;
	while (st[i] != '\0') {
		if (st[i] == '=')
			k++;
		i++;
	}
	return k;
}

int parse_subject(char *s, GostPrivateKey * pkey)
{
	size_t max_size = 500;
	char *string = strndup(s, max_size);
	const char delim[] = ",=";
	char *token, *tok2;
	int i = param_number(string);
	int t = 0;
	int ok=-1;
	token = strtok(string, delim);
	tok2= strtok(NULL, delim);
	if(X509_NAME_add_entry_by_txt(pkey->name, token, MBSTRING_UTF8,
				   tok2, -1, -1, 0)<1)
		printf("В поле X509name ключа не было добавлено %s=%s Ключ будет создан без этого поля!\n",token,tok2); 
	else
		ok=0;
	t++;
	while (t < i) {
		token = strtok(NULL, delim);
		tok2 = strtok(NULL, delim);
		if(X509_NAME_add_entry_by_txt(pkey->name, token, MBSTRING_UTF8,
					   tok2, -1, -1, 0)<1)
			printf("В поле X509name ключа не было добавлено %s=%s Ключ будет создан без этого поля!\n",token,tok2);
		else
			ok=0;
		t++;
	}
	free(string);
	return ok;
}

int certchain_init(STACK_OF(X509) * certs, X509_STORE ** store,X509* mycert)
{
	X509 *bank;
	X509_NAME *namebank;
	
	*store = X509_STORE_new();
	X509_STORE_CTX *vrfy_ctx = X509_STORE_CTX_new();
	int i = 0, t = 0, p = 0;
	for (; i < sk_X509_num(certs); i++) {
		bank = sk_X509_value(certs, i);
		if (!X509_NAME_cmp
		    (X509_get_issuer_name(bank), X509_get_subject_name(bank))) {
			sk_X509_delete(certs, i);
			namebank = X509_get_issuer_name(bank);
			t++;
			break;
		}

	}
	if (!t) {
		printf("Отстуствует корневой сертификат в цепочке!\n");
		goto end;
	}
	X509_STORE_add_cert(*store, bank);
	X509_STORE_CTX_init(vrfy_ctx, *store, bank, NULL);
	X509_verify_cert(vrfy_ctx);
	X509_STORE_CTX_cleanup(vrfy_ctx);
	X509_free(bank);
	if (sk_X509_num(certs) == 0) {
		X509_STORE_CTX_init(vrfy_ctx, *store, mycert, NULL);
		p= X509_verify_cert(vrfy_ctx);
		if(p!=1)
			printf("Цепочка сертификатов не построена!Указанный в --oppo-cert сертификат не образует цепочку с --ca-cert сертификатами!\n");
		goto end;
	}
	while (sk_X509_num(certs) > 0) {
		t = 0;
		for (i = 0; i < sk_X509_num(certs); i++) {
			bank = sk_X509_value(certs, i);
			if (!X509_NAME_cmp
			    (X509_get_issuer_name(bank), namebank)) {
				bank = sk_X509_delete(certs, i);
				namebank = X509_get_subject_name(bank);
				t++;
				break;
			}
		}
		if (!t) {
			printf("Цепочка сертификатов не построена!Не удалось построить цепочку из --ca-cert сертификатов!\n");
			goto end;
		}
		X509_STORE_CTX_init(vrfy_ctx, *store, bank, NULL);
		p = X509_verify_cert(vrfy_ctx);
		if (p != 1) {
			printf("Проблема с верификацией");
			goto end;
		}
		X509_STORE_add_cert(*store, bank);
		X509_free(bank);
		X509_STORE_CTX_cleanup(vrfy_ctx);
	}
	X509_STORE_CTX_init(vrfy_ctx, *store, mycert, NULL);
	p= X509_verify_cert(vrfy_ctx);
	if(p!=1)
		printf("цепочка сертификатов не построена!Указанный в --oppo-cert сертификат не образует цепочку с --ca-cert сертификатами!\n");
end:
	X509_STORE_CTX_free(vrfy_ctx);
	X509_free(mycert);
	if ((p != 1) || (!t)) {
		X509_STORE_free(*store);
		return -1;
	}
	return 1;
}

int check_certs(X509 *mycert,X509* oppcert)
{
	if((mycert==NULL)||(oppcert==NULL))
	{
		if(mycert!=NULL)
			X509_free(mycert);
		if(oppcert!=NULL)
			X509_free(oppcert);
		return -1;
	}
	int flag=0;
		if(X509_get_ext_by_NID(mycert,NID_basic_constraints,-1)>-1)
		{
			flag++;
			printf("Вы используете сертификат УЦ как свой!\n");
		}

		if(X509_get_ext_by_NID(oppcert,NID_basic_constraints,-1)>-1)
		{
			flag++;
			printf("Оппонент использует сертификат УЦ как свой!\n");
		}
		X509_free(mycert);
		X509_free(oppcert);
		if(flag>0)
			return -1;
		return 0;
}
int check_exten(X509* cert)
{
	int ret=0;
	int extpos=0;
	unsigned char* octetexten=NULL;
	X509_EXTENSION* myext=NULL;
		if(extpos=X509_get_ext_by_NID(cert,NID_basic_constraints,-1)<0)
	{
		printf("В указанном в --ca-cert сертфикате CA!=TRUE.\n");
		return 0;
	}
	else
		if((extpos=X509_get_ext_by_NID(cert,NID_key_usage,-1))>-1)
			{
				 myext=X509_get_ext(cert,extpos);
				 ASN1_STRING *bank=X509_EXTENSION_get_data(myext);
				 if(ASN1_STRING_length(bank)!=4)
						return 0;
				 int i=0;
				 octetexten=(unsigned char*)malloc(ASN1_STRING_length(bank));
				 memcpy(octetexten,(unsigned char*)ASN1_STRING_data(bank),ASN1_STRING_length(bank));
				 if(octetexten[0]!=3){
					 printf("В указанном сертификате --ca-cert Key Usage представлен не BIT STIRNG!Критическая ошибка!\n");
					 free(octetexten);
					 return 0;
				 }
				 if(octetexten[1]!=2){
					 printf("В указаном сертификате --ca-cert повреждена длинна в KEY USAGE!Критическая ошибка!\n");
					 free(octetexten);
					 return 0;
				 }
				 if(octetexten[2]>2){
					 printf("В указаном сертификате --сa-cert некорректное количество unused bits!Критическая ошибка!\n");
					 free(octetexten);
					 return 0;
				 }
				 extpos=octetexten[ASN1_STRING_length(bank)-1];
				 if(!(extpos & 4)){
						printf("В указанном в --ca-cert сертификате KEY_CERT_SIGN не взведен!!\n");
						free(octetexten);
						return 0;
				 }
			}
		else
			return 0;

		free(octetexten);
		return 1;
}
