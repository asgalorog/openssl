#include <openssl/bio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "cms_mess.h"
#include "rw_cert_and_key.h"
#include "gencert.h"
#include <string.h>
#include <signal.h>

#define MAX(a,b) (((a)>(b))?(a):(b))

#define BUF_SIZE 7677721
#define MAX_LEN 7000000
#define BUF2_SIZE 4096000
#define PORT 56978

static volatile int sigflag = 0;

static void sighandler(int signo)
{
	sigflag = 1;
	signo = signo;		/* Happy compiler */
}

int sizemess(unsigned char *bank)
{
	int size = 0, i = 0, j = 0;
	if(!(*bank & 128))
		return -1;
	size = *bank & 127;
	if (size > 3)
		return -1;
	for (; j < size; j++) {
		i += bank[j + 1] * (1 << 8 * (size - 1 - j));
	}
	i = i + 2 + size;
	if (i > MAX_LEN)
		return -1;
	return i;
}

int sock_init_client(char *ipport)
{
	int client_sock;
	int val;
	struct sockaddr_in addr;
	client_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (client_sock < 0) {
		printf("client socket error \n");
		return -1;
	}
	char *port;
	char *ip;
	int i = 0;
	for (; i < strlen(ipport); i++)
		if (ipport[i] == ':')
			break;
	if (strlen(ipport) - i < 2) {
		printf("порт не указан!\n");
		return -1;
	}
	ip = malloc(i + 1);
	strncpy(ip, ipport, i);
	ip[i] = '\0';
	port = malloc(strlen(ipport) - i);
	strcpy(port, ipport + i + 1);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atol(port));
	if (inet_aton(ip, &addr.sin_addr) == 0) {
		printf("Ошибка в указанном ip адресе\n");
		free(ip);
		free(port);
		return -1;
	}
	if (connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("client connect fail \n");
		free(port);
		free(ip);
		return -1;
	}
	val = fcntl(client_sock, F_GETFL, 0);
	fcntl(client_sock, F_SETFL, val | O_NONBLOCK);
	free(port);
	free(ip);
	return client_sock;
}

int sock_init_server(char *port)
{
	int server_sock, sock;
	int val;
	struct sockaddr_in addr;
	server_sock = socket(AF_INET, SOCK_STREAM, 0);	//SOCK_STREAM | SOCK_NONBLOCK???
	if (server_sock < 0) {
		printf("Prolem with creat socket \n");
		return -1;
	}
	if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &(int) {
		       1}, sizeof(int)) < 0)
		error("reuse addr fail\n");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atol(port));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf
		    ("bind не сработал!Попробуйте другой порт\n");
		return -1;
	}
	listen(server_sock, 1);
	sock = accept(server_sock, NULL, NULL);
	if(sock!=-1) {
		val = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, val | O_NONBLOCK);
	}
	return sock;
}

unsigned char *decode_mess(int s_read, char *sockread, X509 * mycert,
			   X509 * oppcert, EVP_PKEY * mykey, X509_STORE * store,
			   int *ctrl, int *refseqno)
{
	unsigned char *buff = (unsigned char *)malloc(s_read);
	memcpy(buff, sockread, s_read);
	BIO *data = read2_cms(mycert, oppcert, mykey, store, buff, s_read);
	if (data == NULL) {
		*ctrl = -1;
		free(buff);
		return NULL;
	}
	unsigned char *buff2 = cms_decode(data, ctrl, refseqno);
	free(buff);
	BIO_free(data);
	return buff2;
}

int encode_mess(unsigned char *sockwrite, int *s_write, int NID,
		unsigned char *message, unsigned char *filename, int seqno,
		int command, int refseqno, X509 * mycert, X509 * oppocert,
		EVP_PKEY * mykey,int p_write)
{
	unsigned char *buff = NULL;
	int length = 0;
	BIO *data = NULL;
	data = PSM_start(NID, message, filename, seqno, command, refseqno);
	if ( data == NULL)
		return -1;
	if (create_cms(data, mycert, oppocert, mykey, &buff, &length) < 0) {
		BIO_free(data);
		printf
		    ("Ваш ключ-сертификат не соответсвуют друг другу\n");
		return -1;
	}
	BIO_free(data);
	if(sockwrite==NULL){
		free(buff);
		return 1;
	}
	memcpy(sockwrite + *s_write+p_write, buff, length);
	*s_write += length;
	free(buff);
	return 1;
}
int dummy_check(unsigned char* buff, int r)//Вот в чем моя концепиция: пусть read(stdio) вычитал r байт, может так случиться что код последнего символа будет разделен,поэтому проверим что лежит в конце буфера,если символ-то все ок, иначе запомним i+1 байт до следующего вычитывания.
{
	int ret=0;
	int i=0;
	if(buff[r-1]<128)
		return ret;
	if((buff[r-1] & 0xc0)!=0x80)
		return 1;
	while((buff[r-1-i]& 0xc0)==0x80){
		i++;
		if(i==8)
			return -1;
	}
	if((buff[r-1-i] & 0xe0)==0xc0)//вообще тут нужен хитрый for
	{
		if (i==1)
			return 0;
		return i+1;
	}
	if((buff[r-1-i] & 0xf0)==0xe0)
	{
		if(i==2)
			return 0;
		return i+1;
	}
	if((buff[r-1-i] & 0xf0)==0xf8)
	{
		if(i==3)
			return 0;
		return i+1;
	}
	if((buff[r-1-i] & 0xfc)==0xf8)
	{
		if(i==4)
			return 0;
		return i+1;
	}
	if((buff[r-1-i] & 0xe0)==0xc0)
	{
		if(i==5)
			return 0;
		return i+1;
	}
	return -1;
}
int tcp_main(int flag, X509 * mycert, X509 * oppcert, X509_STORE * store,
	     EVP_PKEY * mykey, char *ipport)
{
	unsigned char *sockread = (unsigned char *)malloc(BUF_SIZE);
	unsigned char *sockwrite = (unsigned char *)malloc(BUF_SIZE);
	unsigned char *outbuff = (unsigned char *)malloc(BUF2_SIZE);
	unsigned char *inbuff = (unsigned char *)malloc(BUF2_SIZE);
	int s_read = 0, s_write = 0;	//сколько прочитанно из сокета и нужно записать в него соответственно
	int o_write = 0, i_read = 0;	//что и выше но I/O
	int p_read = 0, p_write = 0;	//отступы для буферов сокета
	int need2read = 5;	//сколько читать из сокета(сначала первые 5 байт для препарсинга)
	int sock;
	int ok = 1;
	int seqno = 1;
	int backtostream=0;
	int r;
	int oldseqno = 1;
	int readavflag = 0;	//0-читаем начало следующего сообщения,1 прочитали сообщение(т.е. можно расшифровывать),2-надо что то дочитать
	int ctrl = 0;		//управляющая переменная
	int refseqno = -1, oppseqno = 0,lastseqno=0;	//refseqno тоже иногда как управляющая выступает
	int refseqnoflag = 0;	//пришло ли refsqeno на прошлое сообщение
	int endflag = 0;	//начинаем заканчивать общаться
	int sockflag = 0;	//оппонент решил закончить общаться
	int dumpflag=0;
	fd_set rd, wr;
	struct timeval time;
	unsigned char *decmess = NULL;
	unsigned char *bank = NULL;	//для разных целей(файл или препарсинг)
	/**************Генерация первого сообщения для клиента и тестовая проверка для сервера***************/
	if (!flag){ 
		if (encode_mess
		    (sockwrite, &s_write, NID_psm_comm, "hi!", NULL, seqno,
		     PSM_COMMAND_HELLO, 0, mycert, oppcert, mykey,0) < 0) {
			goto err;
		}
}
	else 
		if(encode_mess(NULL,NULL,NID_psm_comm,"test",NULL,0,PSM_COMMAND_HELLO, 4, mycert, oppcert, mykey,0)<0)
		{
			goto err;
		}
	/**********Настройка сокета**********/
	if (flag)
		sock = sock_init_server(ipport);
	else {
		oldseqno = 1;
		sock = sock_init_client(ipport);
	}
	if (sock == -1)
		goto err;
	/**********Настройки для select*******/
	int val = fcntl(STDIN_FILENO, F_SETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, val | O_NONBLOCK);
	val = fcntl(STDOUT_FILENO, F_SETFL, 0);
	fcntl(STDOUT_FILENO, F_SETFL, val | O_NONBLOCK);
	int ndfs = MAX(MAX(STDIN_FILENO, STDOUT_FILENO), sock) + 1;
	/*********Настройка обработки сигналов**/
	struct sigaction sa = { 0 };
	sigset_t newset;
	sigemptyset(&newset);
	sigaddset(&newset, SIGPIPE);
	sigprocmask(SIG_BLOCK, &newset, 0);
	sa.sa_handler = &sighandler;
	sigaction(SIGINT, &sa, NULL);
	/********Начало общения!************/

	while (1) {
		FD_ZERO(&rd);
		FD_ZERO(&wr);
		time.tv_sec = 1;
		time.tv_usec = 10;
// VOVA. 60.00001 секунд? :))) Одна стотысячная секунды что-то решает? :)
		if (readavflag == 1) {
			decmess =
			    decode_mess(s_read, sockread, mycert, oppcert,
					mykey, store, &ctrl, &refseqno);
			if (ctrl == -1) {
				printf
				    ("Сообщение не было декодировано!\n");
				close(sock);
				ok = 0;
				goto err;
			}
			if (decmess != NULL) {
				memcpy(outbuff, decmess, strlen(decmess));
				o_write += strlen(decmess);
				free(decmess);
			}
			if (refseqno < 0) {
				if ((oppseqno + 1) == ctrl)
					oppseqno = ctrl;
				else {
					printf
					    ("В последнем сообщении от оппонета было нарушено секно!%d!=%d\n",
					     oppseqno, ctrl);
					close(sock);
					ok = 0;
					goto err;
				}
				seqno++;
				if (refseqno == -3) {//Пришел goodbye от оппонета. Отвечаем ему.
					encode_mess(sockwrite, &s_write,
						    NID_psm_comm, "bye bye!",
						    NULL, seqno,
						    PSM_COMMAND_ACK, ctrl,
						    mycert, oppcert, mykey,p_write);
					sockflag = 1;
				} else
					encode_mess(sockwrite, &s_write,
						    NID_psm_comm, NULL, NULL,
						    seqno, PSM_COMMAND_ACK,
						    ctrl, mycert, oppcert,
						    mykey,p_write);
			}
			if (refseqno == 0) {
				oppseqno = ctrl;
				if (encode_mess
				    (sockwrite, &s_write, NID_psm_comm,
				     "Hello!", NULL, seqno, PSM_COMMAND_ACK,
				     ctrl, mycert, oppcert, mykey,0) < 0) {
					close(sock);
					goto err;
				}
				refseqnoflag = 1;
			}
			if (refseqno > 0) {
				if (((oldseqno == refseqno)
				     || (seqno == refseqno)||(lastseqno==refseqno))
				    && (oppseqno + 1 == ctrl)) {
					oppseqno = ctrl;
					refseqnoflag = 1;
				} else {
					printf
					    ("seqno=%d oldseqno=%d refseqno=%d oppseqno=%d ctrl=%d \n",
					     seqno, oldseqno, refseqno,
					     oppseqno, ctrl);
					close(sock);
					goto err;
				}
			}
			need2read = 5;
			p_read = 0;
			readavflag = 0;
			s_read = 0;
		}
		/***********Обработка сигнала*****/
		if (sigflag) {            
			if (!dumpflag) {
				seqno++;
				lastseqno=seqno;
				encode_mess(sockwrite, &s_write, NID_psm_comm,
					    "goodbye!", NULL, seqno,
					    PSM_COMMAND_GOODBYE, 0, mycert,
					    oppcert, mykey,p_write);
				dumpflag=1;
			}
		}
		//Если на последнее наше сообщение пришел ACK, больше нечего писать(т.е все данные,включая ACK на PSM_COMMAND_GOODBYE из буфера ушли), то shutdown
			if(!s_write && sockflag && refseqnoflag && !endflag){
				shutdown(sock,SHUT_WR);
				endflag=1;
			}
		if ((i_read < BUF_SIZE) && (!sigflag) && (refseqnoflag) &&(!sockflag)) {
			FD_SET(STDIN_FILENO, &rd);
		}
		if (s_read < BUF_SIZE) {
			FD_SET(sock, &rd);
		}
		if (s_write > 0) {
			FD_SET(sock, &wr);
		}
		if (o_write > 0) {
			FD_SET(STDOUT_FILENO, &wr);
		}
		select(ndfs, &rd, &wr, NULL, &time);
		if (FD_ISSET(STDOUT_FILENO, &wr)) {
			r = write(STDOUT_FILENO, outbuff, o_write);
			o_write = 0;
		}
		if (FD_ISSET(sock, &rd)) {
			r = read(sock, sockread + p_read, need2read);
			if (r < 0)
				if (errno != EINTR && errno != EWOULDBLOCK
				    && errno == EAGAIN) {
					printf("%s\n", strerror(errno));
					close(sock);
					ok = 0;
					goto err;
				} else
					continue;
			if (r == 0) {
				if((sockflag)||(sigflag))//корректное завершение!
					break;
				printf
				    ("Связь была оборвана!\n");
				close(sock);
				goto err;
			}
			if (readavflag == 0) {
				bank = (unsigned char *)malloc(4);
				memcpy(bank, sockread + 1, 4);
				s_read = sizemess(bank);
				free(bank);
				if (s_read == -1) {
					printf("We under attack!!!!\n");
					close(sock);
					goto err;
				}
			}
			need2read = s_read - p_read - r;
			if (need2read != 0) {
				readavflag = 2;
				p_read += r;
			} else {
				readavflag = 1;
			}
		}
		if (FD_ISSET(sock, &wr)) {
			r = write(sock, sockwrite + p_write, s_write);
			if (r < 0)
				if (errno == EINTR) {
					ok = 0;
					printf("%s\n", strerror(errno));
					goto err;
				}
			if (r < s_write) {
				s_write -= r;
				p_write += r;
			} else {
				s_write = 0;
				p_write = 0;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &rd)) {
			r = read(STDIN_FILENO, inbuff+backtostream, BUF2_SIZE-backtostream);
			if (r == 0)
				if (!isatty(STDIN_FILENO)){
					raise(SIGINT);
					continue;
				}
			if(r<0){
				 printf("%s\n", strerror(errno));
				 goto err;
			}
			bank = (unsigned char *)malloc(r+backtostream);
			memcpy(bank, inbuff, r+backtostream);
			int t = oldseqno;	//получается что мы храним только секно сообщений,а секно сообщений для refseqno не храним,поэтому не всегда oldseqno==seqno-5
			oldseqno = seqno+1;
			seqno++;
			if (strncmp(bank, "file:", 5)) {
				 backtostream=dummy_check(bank,r);
				 if(backtostream<0){
					 printf("В входном потоке символы не в utf-8\n");
					 free(bank);
					 close(sock);
					 goto err;
				 }
				if(encode_mess(sockwrite, &s_write, NID_psm_text,
					    bank, NULL, seqno, 0, r-backtostream, mycert,
					    oppcert, mykey,p_write)<0)
				{
					free(bank);
					close(sock);
					goto err;
				}
				int j=0;
				for(;j<backtostream;j++)
					inbuff[j]=bank[r-1-j];
			} else {
				unsigned char *filename =
				    (unsigned char *)malloc(r - 5);
				memcpy(filename, bank + 5, r - 6);
				filename[r - 6] = '\0';
				if (encode_mess
				    (sockwrite, &s_write, NID_psm_file, NULL,
				     filename, seqno, 0, 0, mycert, oppcert,
				     mykey,p_write) < 0) {
					oldseqno = t;
					seqno--;
					free(bank);
					free(filename);
					continue;
				}
				free(filename);
			}
			free(bank);
			refseqnoflag = 0;
		}
	}
	close(sock);
 err:
	free(sockread);
	free(sockwrite);
	free(outbuff);
	free(inbuff);
	return ok;
}
