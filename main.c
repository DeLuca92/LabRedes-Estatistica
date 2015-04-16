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

  struct ether_header header;

  int offset = 0;
  int count_packet = 0;
  int count_ipv4  = 0;
  int count_ipv6  = 0;
  int count_arp_request   = 0;
  int count_arp_reply     = 0;
  int count_icmp  = 0;
  int count_tcp   = 0;
  int count_udp   = 0;
  int count_http   = 0;
  int count_dns   = 0;
  int min_size_packet = 0;
  int max_size_packet = 0;

void printArp(struct ether_arp etherArp){
	printf("\n--ARP HEADER--");
	int i;
	printf("\n/* Format of hardware address.  */ %04x",htons(etherArp.ea_hdr.ar_hrd));
    printf("\n/* Format of protocol address.  */ %04x",htons(etherArp.ea_hdr.ar_pro));
    printf("\n/* Length of hardware address.  */ %02x",etherArp.ea_hdr.ar_hln);
    printf("\n/* Length of protocol address.  */ %02x",etherArp.ea_hdr.ar_pln);
    printf("\n/* ARP opcode (command).  */ %04x",htons(etherArp.ea_hdr.ar_op));

	printf("\n--ARP DATA--");
	printf("\n/* sender hardware address */ ");
	for(i = 0; i < ETH_ALEN ; i++){
		printf("%02x " , etherArp.arp_sha[i]);
	}
	printf("\n/* sender protocol address */ ");
	for(i = 0; i < 4 ; i++){
		printf("%02x " , etherArp.arp_spa[i]);
	}		
	printf("\n/* target hardware addres */ ");

	for(i = 0; i < ETH_ALEN ; i++){
		printf("%02x " , etherArp.arp_tha[i]);
	}
	printf("\n/* target protocol address */ ");
	for(i = 0; i < 4 ; i++){
		printf("%02x " , etherArp.arp_tpa[i]);
	}
}

void printRaw(){
		int i;
		printf("\n");
		for(i = 0; i <= BUFFSIZE ; i++){
		printf("%02x " , buff1[i]);
		}
}

void printEthernet(struct ether_header header){
	printf("\n--ETHERNET HEADER--");
	int i;
	printf("\n/* destination eth addr */ ");
	for(i = 0; i <= 5 ; i++){
		printf("%02x " , header.ether_dhost[i]);
	}
	printf("\n/*source ether address*/ ");
	for(i = 0; i <= 5 ; i++){
		printf("%02x " , header.ether_shost[i]);
	}
	printf("\n/* packet type ID field	*/ %04x",htons(header.ether_type));
}

void countpacket(struct ether_header header){
	//Fix this :@
	count_packet++;
	if(htons(header.ether_type) == ETHERTYPE_IP){
		count_ipv4++;

	}
	else if(htons(header.ether_type) == ETHERTYPE_IPV6){
		count_ipv6++;
	}
	else if(htons(header.ether_type) == ETHERTYPE_ARP){

		struct ether_arp etherArp;
		memcpy(&etherArp, &buff1[offset] , sizeof(etherArp));
		if (htons(etherArp.ea_hdr.ar_op) == ARPOP_REQUEST)
		{
			printf("\nARPOP_REQUEST");
			count_arp_request++;
		}
		else if (htons(etherArp.ea_hdr.ar_op) ==ARPOP_REPLY)
		{
			printf("\nARPOP_REPLY");
			count_arp_reply++;	
		}

		printEthernet(header);
		printArp(etherArp);
		printRaw();
		offset += sizeof(struct ether_arp);
	}
}

void printStatistics(){
	printf("\npackets: %d",count_packet);
	printf("\tpackets IPV4: %d",  count_ipv4);
	printf("\tpackets IPV6: %d",  count_ipv6);
	//printf("\tpackets ARP: %d\n", count_arp_reply);
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
		struct ether_header current;
		offset = 0;
		//int offset = sizeof(ether_header);
		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		memcpy(&current, &buff1, sizeof(current));

		offset += sizeof(current);
		//recv(sockd,&current, sizeof(current), 0x0);
		countpacket(current);
		printStatistics();
		//printRaw();
	}
	
}
