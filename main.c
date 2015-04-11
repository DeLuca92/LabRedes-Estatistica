/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;


typedef struct  {
	uint8_t mac_destino[6];
	uint8_t mac_origem[6];
	uint8_t type[2];
}ethernet_header;

ethernet_header header;

void fillMacOrigem(unsigned char *buff1){
	int i;
	for(i = 0; i <= 11 ; i++){
		header.mac_destino[i] = buff1[i];
	}
}

void fillMacDestino(unsigned char *buff1){
	int i;
	for(i = 6; i <= 11 ; i++){
		header.mac_destino[i] = buff1[i];
	}
}

int main(int argc,char *argv[])
{
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "eth0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		ethernet_header current;
		fillMacOrigem(buff1);
		fillMacDestino(buff1);
		// impress�o do conteudo - exemplo Endereco Destino e Endereco Origem
		printf("MAC Destino: %02x:%02x:%02x:%02x:%02x:%02x \n", header.mac_destino[0],header.mac_destino[1],header.mac_destino[2],
									header.mac_destino[3],header.mac_destino[4],header.mac_destino[5]);
		printf("MAC Origem: %02x:%02x:%02x:%02x:%02x:%02x \n", header.mac_destino[6],header.mac_destino[7],header.mac_destino[8],
									header.mac_destino[9],header.mac_destino[10],header.mac_destino[11]);
		printf("Type : %02x  %02x\n\n" ,buff1[12], buff1[13] );
	}
}
