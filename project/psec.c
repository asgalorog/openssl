#include <openssl/conf.h>
#include <stdint.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>
#include <stdlib.h>
#include <getopt.h>
#include <stddef.h>
#include "rw_cert_and_key.h"
#include "gencert.h"
#include "cms_mess.h"
#include "tcppsec.h"
int main(int argc, char **argv)
{
	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();
	const struct option long_opt[] = {
		{"key-params", required_argument, NULL, 'p'},
		{"subject", required_argument, NULL, 's'},
		{"key-out", required_argument, NULL, 'o'},
		{"help", no_argument, NULL, 'h'},
		{"issuer-key", required_argument, NULL, 'i'},
		{"subject-key", required_argument, NULL, 'b'},
		{"ca", no_argument, NULL, 'c'},
		{"validity", required_argument, NULL, 'v'},
		{"serial", required_argument, NULL, 'r'},
		{"cert-out", required_argument, NULL, 'e'},
		{"ca-cert", required_argument, NULL, 't'},
		{"my-cert", required_argument, NULL, 'm'},
		{"oppo-cert", required_argument, NULL, 'u'},
		{"my-key", required_argument, NULL, 'k'},
		{"flag", required_argument, NULL, 'f'},
		{"ip", required_argument, NULL, 'x'},
		{"port",required_argument, NULL, 'x'},
		{0, 0, 0, 0}
	};
	int opt_index = 0;
	int rez;
	int kfalg = 0, x509flag = 0, tcpflag = -1, flag;	//флаги того что пользователь хочет использовать --key или --cert
	char *keyparams = NULL;
	char *subname = NULL;
	char *keyout = NULL;
	char *issuerkey = NULL;
	char *subjkey = NULL;
	char *certout = NULL;
	char *mycert = NULL;
	char *oppcert = NULL;
	char *mykey = NULL;
	char *ipport = NULL;
	int CAnumber=0;
	int valid = -1;
	int serial = -1;
	int bsuc=0;
	int ok=0;
	X509* test=NULL;
	X509_free(test);
	STACK_OF(X509) * certs = sk_X509_new_null();
	if(argc==1)
	{
		printf("Не были указаны никакие параметры!\nДля справки наберите ./psec.sh --help\n");
		goto end;
	}
	if (!strncmp(argv[1], "key", 3)){
		kfalg = 1;
		ok=1;
	}
	if (!strncmp(argv[1], "cert", 4)){
		x509flag = 1;
		ok=1;
	}
	if (!strncmp(argv[1], "client", 6)){
		tcpflag = 0;
		ok=1;
	}
	if (!strncmp(argv[1], "server", 6)){
		tcpflag = 1;
		ok=1;
	}
	if (!strncmp(argv[1],"--help",6))
		ok=1;
	if(!ok){
		printf("Ошибка команды!Для справки наберите ./psec.sh --help\n");
		goto end;
	}
	if(isatty(0))
	if (system("stty iutf8") == -1){ 
		printf("Выполните команду stty iutf8, иначе UTF-8 не будет корректно работать!\n");
		ok=0;
		goto end;
	}
	while ((rez =
		getopt_long_only(argc, argv, "", long_opt, &opt_index)) != -1)
		switch (rez) {
		case 'x':
			if (optarg) {
				ipport = optarg;
			}
			break;
		case 'm':
			if (optarg) {
				mycert = optarg;
			}
			break;
		case 'u':
			if (optarg) {
				oppcert = optarg;
			}
			break;
		case 'k':
			if (optarg) {
				mykey = optarg;
			}
			break;
		case 'f':
			if (optarg) {
				flag = atoi(optarg);
			}
			break;
		case 'p':
			if (optarg == "XA") {
				keyparams = "XchA";
			} else if (optarg == "XB") {
				keyparams = "XchB";
			} else {
				keyparams = optarg;
			}
			break;
		case 's':
			if (optarg) {
				subname = optarg;
			}
			break;
		case 'o':
			if (optarg) {
				keyout = optarg;
			}
			break;
		case 'b':
			if (optarg) {
				subjkey = optarg;
			}
			break;
		case 'c':
			x509flag = 2;
			break;
		case 'v':
			if (optarg) {
				valid = atoi(optarg);
			}
			break;
		case 'r':
			if (optarg) {
				serial = atoi(optarg);
			}
			break;
		case 'e':
			if (optarg) {
				certout = optarg;
			}
			break;
		case 'i':
			if (optarg) {
				issuerkey = optarg;
			}
			break;
		case 'h':
			printf
			    ("Общий вид: ./psec.sh <команда> <параметры>\n\nКоманды:\nkey-для генерации закрытого ключа с заданными параметрами(см. ниже)\ncert-для генерации сертификата с заданным ключом и параметрами(см. ниже)\nclient-для инициализации клиента с заданными параметрами(см. ниже)\nserver-для инициализации сервера с заданными параметрами(см. ниже)\n\nОпции:\nДля ключей(key):\n--key-params=X - криптопараметры ключевой пары gost2001, где X={A,B,C,XA,XB,0}\n--subject - Имя X509 субъекта для которого выпускается ключ\n--key-out - имя файла в который будет записан ключ\nДля сертификатов(cert):\n--subject-key - файл закрытого ключа субъекта, для которого создается сертифкат\n--issuer-key - файл закрытого ключа издателя, который подписывает сертификат\n--validity - время действия выпускаемого сертификата\n--serial - серийный номер сертификата\n--cert-out - файл в котором будет храниться сертификат\n--ca - Если присутвует, то обозначает что данный сертификат УЦ\nДля клинта и сервера(client server):\n--my-cert - имя файла в котором лежит сертификат данной строны\n--oppo-cert - имя файла в котором лежит сертификат противоположной стороны\n--my-key - имя файла в котором хранится закрытый ключ данной стороны\n--ca-cert - имя файла в котором хранится сертификат УЦ(может повторятся несколько раз,если существуют промежуточные УЦ)\n--ip=ip:port - опция для клиента.\n--port=port -опция для сервера\n");
			break;
		case 't':
			{	
				X509* bank=NULL;
				bank=read_cert(optarg);
				if(bank!=NULL && check_exten(bank))
					sk_X509_push(certs,bank);
				else
				{
					X509_free(bank);
					goto end;
				}
			break;
			}
		case '?':
			printf("Неправильные опции!Для справки наберите ./psec.sh --help \n");
			ok=0;
			goto end;
		}
	if (kfalg) {
		if ((keyparams == NULL) || (subname == NULL)
		    || (keyout == NULL)||(strlen(keyparams)==0)||(strlen(subname)==0)||(strlen(keyout)==0)) {

			printf("При генерации ключа не был указан один из параметров!\nУказанные параметры:\n--key-params=%s\n--subject=%s\n--key-out=%s\n",keyparams,subname,keyout);
			ok=0;
			goto end;
		} else {
			if (!mykeygen(keyout, keyparams, subname)){
				printf("Ошибка при создании ключа\n");
				ok=0;
			}
			else
				printf("Ключ был успешно сгенерирован\n");

		}
	}
	if (x509flag) {
		if ((issuerkey == NULL) || (subjkey == NULL)
		    || (serial < 1) || (valid < 1)
		    || (certout == NULL)||(strlen(issuerkey)==0)||(strlen(subjkey)==0)||(strlen(certout)==0)) {
			printf
			    ("Не были указаны все необходимые параметры для создания сертфииката!Вот указаныне параметры(если параметр равен -1,NULL или пустоте,то он не был указан):\n--subject-key=%s\n--issuer-key=%s\n--validity=%d\n--serial=%d(помните что по стандартам серийиный номер >0)\n--cert-out=%s\nДля подробной справки наберите ./psec.sh --help\n",subjkey,issuerkey,valid,serial,certout);
			ok=0;
		goto end;
		} 
	 if(x509flag==2)	
		 if (!strcmp(issuerkey, subjkey))

			bsuc=createCAX509(issuerkey, valid, serial, certout);
		else
			bsuc=createX509(issuerkey, subjkey, valid, serial, certout,
				   1);
		 if (x509flag==1)
			bsuc=createX509(issuerkey, subjkey, valid, serial, certout, 0);
		 if(bsuc!=-1){
			printf("сертификат успешно создан %s\n",certout);
		 }
		 else
			 ok=0;
	}
	if (tcpflag > -1) {
		if((mycert==NULL) || (oppcert==NULL) || (ipport==NULL)||(strlen(ipport)==0)||(mykey==NULL)||(strlen(mykey)==0)||(strlen(oppcert)==0)||(strlen(mycert)==0)){
			printf("Не были указаны все необходимые параметы для клинта/сервера!Вот указаные параметры(NULL означает что параметр не был указан):\n--my-cert=%s\n--oppo-cert=%s\n--my-key=%s\n",mycert,oppcert,mykey);
			if(!tcpflag)
				printf("--ip=%s\n",ipport);
			else
				printf("--port=%s\n",ipport);
			ok=0;
			goto end;
		}
			if(check_certs(read_cert(mycert),read_cert(oppcert))<0){
// Типа "проверить и уничтожить"! После прочтения сжечь! :))))))))))))
// Это не замечание. Переделывать не надо. Просто обычно не принято в функциях, которые
// только читают входные данные, что-то менять в этих входных данных, тем более уничтожать.
// Функция check_certs, судя по названию, проверяет сертификаты. То есть, только их читает.
// Интуитивно совершенно непонятно, почему она должна их ещё и уничтожать.
// Такие неясности могут порождать ошибки из-за неправильного понимания.
// Опять же, непонятно, почему мы передаём сразу 2 сертификата. Гораздо более был бы логичен
// код:
// X509* mycert_obj = read_cert(mycert);
// X509* oppcert_obj = read_cert(oppcert);
// if (check_cert(mycert_obj) < 0) goto err;
// if (check_cert(oppcert_obj) < 0) goto err;
// ...
// X509_free(mycert_obj);
// X509_free(oppcert_obj);
// Ruslan Вас понял!
				ok=0;
				goto end;
			}
			X509_STORE *store;
		if (certchain_init(certs, &store,read_cert(oppcert)) < 0){
			ok=0;
			goto end;
		}
		ok=tcp_ctrl(store, mykey, mycert, oppcert, tcpflag, ipport);
		X509_STORE_free(store);
	}
end:
	sk_X509_pop_free(certs,X509_free);
	CONF_modules_unload(1);
	EVP_cleanup();
	ENGINE_cleanup();
	CONF_modules_free();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return !ok;

}
