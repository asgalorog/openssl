#include "cms_mess.h"
#include <openssl/cms.h>
#include "rw_cert_and_key.h"
#include "gencert.h"
#include <locale.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#define MAX_LEN 7000000
BIO *PSM_comm(int command, char *text, int refseqno, int seqno)
{
	PSEC_MESSAGE *my_mess = PSEC_MESSAGE_new();
	my_mess->mtype = OBJ_nid2obj(NID_psm_comm);
	my_mess->seqno = ASN1_INTEGER_new();
	ASN1_INTEGER_set(my_mess->seqno, seqno);
	my_mess->d.psmcomm = M_ASN1_new_of(PSMCommand);
	ASN1_INTEGER_set(my_mess->d.psmcomm->command, command);
	if (refseqno) {
		my_mess->d.psmcomm->refseqno = ASN1_INTEGER_new();
		ASN1_INTEGER_set(my_mess->d.psmcomm->refseqno, refseqno);
	}
	if (text != NULL)
		ASN1_STRING_set(my_mess->d.psmcomm->text, (const char *)text,
				-1);
	unsigned char *buff = NULL;
	int length = i2d_PSEC_MESSAGE(my_mess, &buff);
	BIO *out = BIO_new(BIO_s_mem());
	BIO_write(out, buff, length);
	free(buff);
	PSEC_MESSAGE_free(my_mess);
	return out;
}
char* name_without_dir(char* file)
{
	int i=0;
	int t=0;
	char *newname;
	for(;i<strlen(file);i++)
	{
		if(file[i]=='/')
			t=i;
	}
	if (t==0){
		newname=strdup(file);
		return newname;
	}
	newname=strdup(file+t+1);
	return newname;
}
BIO *PSM_file(char *file, int seqno)
{
	off_t length=0;
	struct stat *buf=(struct stat *)malloc(sizeof(struct stat));
	PSEC_MESSAGE *my_mess = PSEC_MESSAGE_new();
	my_mess->mtype = OBJ_nid2obj(NID_psm_file);
	my_mess->seqno = ASN1_INTEGER_new();
	ASN1_INTEGER_set(my_mess->seqno, seqno);
	my_mess->d.file = M_ASN1_new_of(PSMFile);
	if (stat(file,buf)) {
		printf("%s\n", strerror(errno));
		free(buf);
		PSEC_MESSAGE_free(my_mess);
		return NULL;
	}
	//stat(file,buf);
	length=buf->st_size;
	free(buf);
	if(length>MAX_LEN){
		printf("Файл слишком большой!\n");
		PSEC_MESSAGE_free(my_mess);
		return NULL;
	}

	unsigned char *buff = (char *)malloc(length);
	BIO *infile = NULL;
	infile = BIO_new_file(file, "rb");
	BIO_read(infile, buff, length);
	BIO_free(infile);
	ASN1_STRING_set(my_mess->d.file->file,buff,
			length);
	char *newname=name_without_dir(file);
	ASN1_STRING_set(my_mess->d.file->name,newname,-1);
	unsigned char *buff2 = NULL;
	length = i2d_PSEC_MESSAGE(my_mess, &buff2);
	BIO *out = BIO_new(BIO_s_mem());
	BIO_write(out, buff2, length);
//	BIO *test = BIO_new_file("file2.der", "w");
//	BIO_write(test, buff2, length);
//	BIO_free(test);
	free(buff);
	free(newname);
	PSEC_MESSAGE_free(my_mess);
	free(buff2);
	return out;
}

BIO *PSM_text(unsigned char *text, int seqno, int size)
{
	PSEC_MESSAGE *my_mess = PSEC_MESSAGE_new();
	ASN1_UTF8STRING *utf8_text = NULL;
	my_mess->mtype = OBJ_nid2obj(NID_psm_text);
	my_mess->seqno = ASN1_INTEGER_new();
	ASN1_INTEGER_set(my_mess->seqno, seqno);
	my_mess->d.text = M_ASN1_new_of(PSMText);
	setlocale(LC_ALL, "ru_RU.UTF-8");
	unsigned int l = 0,i = 0, length;
	long unsigned int c=0;
	int len=7,t=0;
	const unsigned char *p = text;
	char *t_text = text;
	while (size > l) {
		if(size-l<7)
			len=size-l;
		t = UTF8_getc(p + l, len, &c);
		if(t<1)
		{
			PSEC_MESSAGE_free(my_mess);
			printf("Проблемы с локалью!!!\n");
			return NULL;
		}
		if ((!isgraph(c)) && (c != 32) && (c != 1025) && (c != 1105) && ((c < 1040) || (c > 1103)))	//я не справился с локалью((
		{
			if ((l - i) == 0) {
				l += t;
				i = l;
				continue;
			}
			utf8_text = ASN1_UTF8STRING_new();
			ASN1_STRING_set(utf8_text, t_text + i, l - i);
			sk_ASN1_UTF8STRING_push(my_mess->d.text->text,
						utf8_text);
			i = l + t;
		}
		l += t;
	}
	unsigned char *buff2 = NULL;
	length = i2d_PSEC_MESSAGE(my_mess, &buff2);
	if (length < 0){
		printf("problen with i2d text\n");
		 PSEC_MESSAGE_free(my_mess);
		 return NULL;
	}
	BIO *out = BIO_new(BIO_s_mem());
	BIO_write(out, buff2, length);
	PSEC_MESSAGE_free(my_mess);
	free(buff2);
	return out;
}

BIO *PSM_start(int nid_comm,unsigned char *text, char *name, int seqno, int command,
	       int refseqno)
{
	BIO *ret = NULL;
	switch (nid_comm) {
	case NID_psm_comm:
		ret = PSM_comm(command, text, refseqno, seqno);
		return ret;
		break;
	case NID_psm_text:
		ret = PSM_text(text, seqno, refseqno);
		return ret;
		break;
	case NID_psm_file:
		ret = PSM_file(name, seqno);
		return ret;
	default:
		printf("Underfined command!\n");
		return NULL;

	}
}

unsigned char *psm_comm_decode(PSEC_MESSAGE * my_mess, int *ctrl, int *refseqno)
{
	unsigned char *ret = NULL;
	if (ASN1_STRING_length(my_mess->d.psmcomm->text) != 0) {
		ret =
		    (unsigned char *)
		    malloc(ASN1_STRING_length(my_mess->d.psmcomm->text)+2);
		memcpy(ret, ASN1_STRING_data(my_mess->d.psmcomm->text),
		       ASN1_STRING_length(my_mess->d.psmcomm->text));
		*(ret+ASN1_STRING_length(my_mess->d.psmcomm->text))='\n';
		*(ret+ASN1_STRING_length(my_mess->d.psmcomm->text)+1)='\0';

	}
	switch (ASN1_INTEGER_get(my_mess->d.psmcomm->command)) {
	case PSM_COMMAND_HELLO:
		*ctrl = ASN1_INTEGER_get(my_mess->seqno);
		*refseqno = 0;
		break;
	case PSM_COMMAND_ACK:
		*ctrl = ASN1_INTEGER_get(my_mess->seqno);
		*refseqno = ASN1_INTEGER_get(my_mess->d.psmcomm->refseqno);
		break;
	case PSM_COMMAND_GOODBYE:
		*ctrl = ASN1_INTEGER_get(my_mess->seqno);
		*refseqno = -3;
		break;
	default:
		*ctrl=-1;
		printf("В PSM_COMMAND оказалась неизвестная комманда!Критическая ошибка!\n");
		break;
	}
	return ret;
}

unsigned char *psm_text_decode(PSEC_MESSAGE * my_mess, int *ctrl)
{
	unsigned char *ret = NULL, *p;
	*ctrl = ASN1_INTEGER_get(my_mess->seqno);
	int i, length = 0;	//length- размер строки,которую вернут
	for (i = 0; i < sk_ASN1_UTF8STRING_num(my_mess->d.text->text); i++) {
		ASN1_UTF8STRING *current =
		    sk_ASN1_UTF8STRING_value(my_mess->d.text->text, i);
		length += ASN1_STRING_length(current);
		length += 1;	//разделитель
	}
	length++;
	if(length==1)
		length++;
	ret = (unsigned char *)malloc(length);
	p = ret;
	for (i = 0; i < sk_ASN1_UTF8STRING_num(my_mess->d.text->text); i++) {
		ASN1_UTF8STRING *current =
		    sk_ASN1_UTF8STRING_value(my_mess->d.text->text, i);
		length = ASN1_STRING_length(current);
		if (i > 0)
			*p++ = '\n';
		memcpy(p, (unsigned char *)ASN1_STRING_data(current), length);
		p += length;
	}
	*p++ = '\n';
	*p++ = '\0';
	return ret;
}
unsigned char* genfilename(ASN1_UTF8STRING * oldname)
{
	unsigned int length=ASN1_STRING_length(oldname);
	char* choldname=ASN1_STRING_data(oldname);
	int t=3;
 char* newname=(char*)malloc(length+t);
	memcpy(newname,ASN1_STRING_data(oldname),length);
	if(access(ASN1_STRING_data(oldname),F_OK)==-1){
		newname[length]='\0';
	   return newname;}
	int i=1;
	int b=10;
	/*for(;i<100;i++)
	{
		sprintf(newname,"%s.%d",choldname,i);
		if(access(newname,F_OK)==-1)
		{
			return newname;
		}
	}
*/
	while(1)
	{
		sprintf(newname,"%s.%d",choldname,i);
		if(access(newname,F_OK)==-1)
			return newname;
		i++;
		if(i==b)
		{
			b*=10;
			t++;
			newname=realloc(newname,length+t);
		}
	}
}
unsigned char *psm_file_decode(PSEC_MESSAGE * my_mess, int *ctrl)
{
	unsigned char *ret = NULL;
	int file_len;
	BIO *out = NULL;
	*ctrl = ASN1_INTEGER_get(my_mess->seqno);
	file_len = ASN1_STRING_length(my_mess->d.file->file);
	unsigned char* filename=genfilename(my_mess->d.file->name);
	out = BIO_new_file(filename, "w");
	BIO_write(out, ASN1_STRING_data(my_mess->d.file->file), file_len);
	BIO_free(out);
	return filename;
}

unsigned char *cms_decode(BIO * data, int *cntrl, int *refseqno)
{
		/***/
	//      BIO* test=BIO_new_file("cms_decode_test.txt","w");
	unsigned int length = BIO_ctrl_pending(data);
	unsigned char *buff = (unsigned char *)malloc(length);
	BIO_read(data, buff, length);
	//      printf("\n\n%d\n",length);
	//      BIO_write(test,buff,length);
	//      free(buff);
	PSEC_MESSAGE *my_mess = NULL;
	const unsigned char *buf2 = buff;
	unsigned char *ret = NULL;
	if (!d2i_PSEC_MESSAGE(&my_mess, &buf2, length)) {
		printf("Пришедшее сообщение повреждено или была допущена ошибка в ключах/сертификатах \n");
		free(buff);
		*cntrl = -1;
		return NULL;
	}
	switch (OBJ_obj2nid(my_mess->mtype)) {
	case NID_psm_comm:
		ret = psm_comm_decode(my_mess, cntrl, refseqno);
		break;
	case NID_psm_text:
		ret = psm_text_decode(my_mess, cntrl);
		*refseqno = -1;
		break;
	case NID_psm_file:
		ret = psm_file_decode(my_mess, cntrl);
		*refseqno = -2;
		break;
	default:
		*cntrl=-1;
		printf("У пришедшего сообщения неизвестный NID!Критическая ошибка!\n");
		break;
	}
	PSEC_MESSAGE_free(my_mess);
	free(buff);
	return ret;
}

int create_cms(BIO * data, X509 * mycert, X509 * oppcert, EVP_PKEY * my_key,
	       unsigned char **buff, unsigned int *length)
{
	CMS_ContentInfo *encr_cms = NULL;
	BIO *sign = BIO_new(BIO_s_mem());\
	int ok=1;
	encr_cms =
	    CMS_encrypt(NULL, data, EVP_get_cipherbyname("gost89"),
			CMS_PARTIAL | CMS_BINARY);
	CMS_add1_recipient_cert(encr_cms, oppcert, 0);
	CMS_final(encr_cms, data, NULL, CMS_BINARY);
	//вот тут химичу
	unsigned char *buff2 = NULL;
	int length2 = i2d_CMS_ContentInfo(encr_cms, &buff2);
	BIO_write(sign, buff2, length2);
	//теперь подпишем 
	int flags = CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL;
	CMS_ContentInfo *sign_cms = NULL;
	sign_cms = CMS_sign(NULL, NULL, NULL, sign, flags);
	CMS_add1_signer(sign_cms, mycert, my_key, NULL, flags);
	if(!CMS_final(sign_cms, sign, NULL, flags))
	{
		ok=-1;
		goto err;
	}
	//с der у CMS все плохо, так что ручками делаем
	unsigned char *buff3 = NULL;
	int length3 = i2d_CMS_ContentInfo(sign_cms, &buff3);
	/*************************
	BIO *test_file = BIO_new_file("cms.txt", "wr");
	BIO_write(test_file, buff3, length3);
	BIO_free(test_file);
	*************************/
	*buff = buff3;
	*length = length3;
err:
	BIO_free(sign);
	free(buff2);
	CMS_ContentInfo_free(sign_cms);
	CMS_ContentInfo_free(encr_cms);
	return ok;
}

BIO *read2_cms(X509 * oppcert, X509 * mycert, EVP_PKEY * oppkey,
	       X509_STORE * store, unsigned char *data, unsigned int length)
{
	CMS_ContentInfo *encr_cms = NULL;
	CMS_ContentInfo *sign_cms = NULL;
	PSEC_MESSAGE *psm = NULL;
	STACK_OF(X509) * certs = sk_X509_new_null();
	unsigned int length2 = 0;
	unsigned char *buff=NULL;
	const unsigned char *c_buff;
	BIO* hope=NULL;
	BIO* forchain=NULL;
	c_buff = data;
	/*********************************
	BIO *test_bio = BIO_new_file("read2cms.txt", "w");
	BIO_write(test_bio, data, length);
	BIO_free(test_bio);
	***********************************/
	if (!d2i_CMS_ContentInfo(&sign_cms, &c_buff, length)) {
		printf("problem with d2i sign content!\n");
		goto err;
	}
	sk_X509_push(certs, mycert);
	forchain = BIO_new(BIO_s_mem());
	hope = BIO_new(BIO_s_mem());
	if (!CMS_verify(sign_cms, certs, store, NULL, forchain, CMS_NOINTERN)){
		printf("Ошибка верификации!\n");
		goto err;
	}
	length2 = BIO_ctrl_pending(forchain);
	buff = (unsigned char *)malloc(length2);
	BIO_read(forchain, buff, length2);
	c_buff = buff;
	if (!d2i_CMS_ContentInfo(&encr_cms, &c_buff, length2)){
		printf("Ошибка d2i encrypt content\n");
		goto err;
	}
	if (!CMS_decrypt(encr_cms, oppkey, oppcert, NULL, hope, CMS_BINARY)) 
		printf("Полученное сообщение не было расшифровано!\n");
	/******************
	unsigned char* test_buff;
	unsigned int test_len;
	BIO* test_bio=BIO_new_file("read2cms.txt","w");
	test_len=BIO_ctrl_pending(hope);
	test_buff=(unsigned char*)malloc(test_len);
	BIO_read(hope,test_buff,test_len);
	BIO_write(test_bio,test_buff,test_len);
	BIO_free(test_bio);
	free(test_buff);
	******************/
err:
	CMS_ContentInfo_free(encr_cms);
	CMS_ContentInfo_free(sign_cms);
	free(buff);
	sk_X509_free(certs);
	BIO_free(forchain);
	return hope;
}
int tcp_ctrl(X509_STORE * store, char *f_mykey, char *f_mycert, char *f_oppcert,
	     int flag,char* ipport)
{
	X509 *mycert=NULL;
	GostPrivateKey *gpk=NULL;
	X509 *oppcert =NULL;
	EVP_PKEY *mykey = EVP_PKEY_new();
	int ok=1;
	mycert=read_cert(f_mycert);
	if (mycert == NULL) {
		ok= 0;
		goto err;
	}
	oppcert = read_cert(f_oppcert);
	if (oppcert == NULL) {
		ok= 0;
		goto err;
	}
	gpk = read_key_file(f_mykey);
	if (gpk == NULL) {
		ok= 0;
		goto err;
	}
	if(!gpk_to_evp(mykey, gpk))
	{	
		ok=0;
		goto err;
	}
	ok=tcp_main(flag, mycert, oppcert, store, mykey,ipport);
err:
	GostPrivateKey_free(gpk);
	X509_free(oppcert);
	X509_free(mycert);
	EVP_PKEY_free(mykey);
	return ok;
}
