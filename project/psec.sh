#!/bin/bash
LD_LIBRARY_PATH=$(pwd)/openssl/lib64
export LD_LIBRARY_PATH
OPENSSL_CONF=$(pwd)/openssl/ssl/openssl.cnf
export OPENSSL_CONF
SSL_CERT_DIR=$(pwd)
export SSL_CERT_DIR
if [[ $# = 1 ]] 
then
case "$1" in
	test)
		./psec key --key-params="A" --subject="CN=BOSS,O=FACTOR,C=RU" --key-out="CAkey.der"
		./psec key --key-params="C" --subject="CN=Vladimir,O=FACTOR,C=RU" --key-out="vladimirkey.der"
		./psec key --key-params="B" --subject="CN=Ruslan,O=no,C=RU" --key-out="ruslankey.der"
		./psec key --key-params="B" --subject="CN=sub,O=MIREA,C=RU" --key-out="MIREAkey.der"
		./psec cert --subject-key="CAkey.der" --issuer-key="CAkey.der" --validity=200 --serial=1 --cert-out="CAcert.crt" --ca
		./psec cert --subject-key="MIREAkey.der" --issuer-key="CAkey.der" --validity=200 --serial=5 --cert-out="subca.crt" --ca
		./psec cert --subject-key="ruslankey.der" --issuer-key="MIREAkey.der" --validity=20000 --serial=2 --cert-out="ruslancert.crt"
		./psec cert --subject-key="vladimirkey.der" --issuer-key="CAkey.der" --validity=100 --serial=32144 --cert-out="vladimircert.crt" 
	#	./psec  --my-cert="vladimircert.crt" --oppo-cert="ruslancert.crt" --ca-cert="subca.crt" --ca-cert="CAcert.crt" --my-key="vladimirkey.der" --flag=0
	# ./psec.sh --my-cert="ruslancert.crt" --oppo-cert="vladimircert.crt" --ca-cert="CAcert.crt" --my-key="ruslankey.der" --flag="1"
	#	openssl x509 -inform DER -in CAfactorcert.crt -outform PEM -out ca.pem
	#	openssl x509 -inform DER -in subcert.crt -outform PEM -out sub.pem
	#	openssl x509 -inform DER -in Vladimircert.crt -outform PEM -out sub2.pem
	#	openssl verify -CAfile ca.pem sub.pem 
		;;
		memor)
#		valgrind  --leak-check=full --show-leak-kinds=all --track-origins=yes --num-callers=100 --log-file=keymemZ.txt ./psec key --key-params="A" --subject="jj=asd,asdq=ad"     --key-out="valgCA.der"
#		 valgrind  --leak-check=full --show-leak-kinds=all --track-origins=yes --num-callers=100 --log-file=keymem2.txt ./psec key --key-params="A" --subject="CN=Субъект3,O=Хорошая организация,C=RU" --key-out="testkey.der"
#		  valgrind  --leak-check=full --show-leak-kinds=all --track-origins=yes --num-callers=100 --log-file=valg/keymem3.txt ./psec key --key-params="B" --subject=   --key-out="valgCA.der"
#			./psec key --key-params="A" --subject="CN=WOW" --key-out="valg/valgCA.der"
#			valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=valg/truecertmem.txt ./psec --subject-key="valg/valgCA.der" --issuer-key="valg/valgCA.der" --validity=10 --serial=1 --cert-out="valg/valgsubcert.crt" --ca
#			valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=valg/dircertmem.txt ./psec --subject-key="valg/valgCA.der" --issuer-key="valg/valgCA.der" --validity=10 --serial=1 --cert-out="valg/a/valgCA.crt" --ca
#			valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=valg/serialcertmem.txt ./psec --subject-key="valg/valgCA.der" --issuer-key="valg/valgCA.der" --validity=10 --serial=-5 --cert-out="valg/valgCA.crt" --ca
#		valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=certmem.txt ./psec --subject-key="valgsub.der" --issuer-key="valgCA.der" --validity=10 --serial=1 --cert-out="valgsubcert.crt" --ca
#		valgrind  --leak-check=full --show-leak-kinds=all --track-origins=yes  --log-file=CMSmem.txt ./psec	--subject-key="subjkeytest.der" --issuer-key="CAkeytest.der" --validity=100 --serial=32144 --cert-out="subcerttest.crt"
#		valgrind  --leak-check=full --show-leak-kinds=all --track-origins=yes  --log-file=CMSmem.txt ./psec --ca-cert="subcerttest.crt" --ca-cert="CAtestcert.crt"
#		 valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes  --log-file=tcpmem.txt ./psec server --my-cert="vladimircert.crt" --oppo-cert="CAcert.crt"  --my-key="vladimirkey.der" --port="14548"
#		valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes  --log-file=valg/catcpmem.txt ./psec client --my-cert="subca.crt" --oppo-cert="subca.crt" --ca-cert="CAcert.crt" --ca-cert="subca.crt" --my-key="ruslankey.der" --ip="127.0.0.1:14548"
#			 valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=keymem.txt ./psec cert --subject-key=testkey.der --issuer-key=CAkey.der --validity=2 --serial=5 --cert-out=fakeCA.crt 
			valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=certmem.txt 	./psec client --my-cert="ruslancert.crt" --oppo-cert="vladimircert.crt" --ca-cert="CAcert.crt" --my-key="ruslankey.der" --ip="127.0.01:14548"
#			valgrind  --leak-check=full --show-leak-kinds=all  --num-callers=100 --track-origins=yes --log-file=certmem.txt ./psec server --my-cert="vladimircert.crt" --oppo-cert="vladimircert.crt" --ca-cert="subca.crt" --ca-cert="CAcert.crt"   --my-key="vladimirkey.der" --port="14548"
		;;
	debug)
		gdb -tui ./psec
		;;
	--help)
		./psec --help
		;;
	*)
#		echo "Не хватает агрументов!Для справки наберите ./psec.sh --help"
		./psec "$@"
		;;
esac
else 
./psec "$@"
fi
