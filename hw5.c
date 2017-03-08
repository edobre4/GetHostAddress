#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dns.h"

static int debug=0, nameserver_flag=0;
char rootServers[20][100];
int rs_count = 0;

void usage() {
	printf("Usage: hw5 [-d] -n nameserver -i domain/ip_address\n\t-d: debug\n");
	exit(1);
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
	memset(query,0,max_query);

	in_addr_t rev_addr=inet_addr(hostname);
	if(rev_addr!=INADDR_NONE) {
		static char reverse_name[255];		
		sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
						(rev_addr&0xff000000)>>24,
						(rev_addr&0xff0000)>>16,
						(rev_addr&0xff00)>>8,
						(rev_addr&0xff));
		hostname=reverse_name;
	}

	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(0x0100);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len=to_dns_style(hostname,query+query_len);
	query_len += name_len; 
	
	// now the query type: A or PTR. 
	uint16_t *type = (uint16_t*)(query+query_len);
	if(rev_addr!=INADDR_NONE)
		*type = htons(12);
	else
		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;	
}

int sendDnsQuery(char *hostname, char *nameserver, char *address, char *name) {
        if(debug)
        printf("Resolving %s using server %s.\n", hostname, nameserver);

        char ns_list[50][2][50];
        memset(ns_list, 0, 50*2*50);
        int ns_records = 0;
        int a_records = 0;

	in_addr_t nameserver_addr=inet_addr(nameserver);
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	// construct the query message
	uint8_t query[1500];
	int query_len=construct_query(query,1500,hostname);

	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
	
	int send_count = sendto(sock, query, query_len, 0, (struct sockaddr*)&addr,sizeof(addr));
	if(send_count<0) { 
          perror("Send failed");	
          exit(1); 
        }	

	// await the response 
	uint8_t answerbuf[1500];
        // set timeout to 1 second
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	int rec_count = recv(sock,answerbuf,1500,0);
	
        if (recv < 0) {
          if (errno == EAGAIN) {
            if(debug)
              printf("Timeout occurred\n");
              return 0;
          }
        }
	// parse the response to get our answer
	struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
	uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
	
	// now answer_ptr points at the first question. 
	int question_count = ntohs(ans_hdr->q_count);
	int answer_count = ntohs(ans_hdr->a_count);
	int auth_count = ntohs(ans_hdr->auth_count);
	int other_count = ntohs(ans_hdr->other_count);

	// skip past all questions
	int q;
	for(q=0;q<question_count;q++) {
		char string_name[255];
		memset(string_name,0,255);
		int size=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr+=size;
		answer_ptr+=4; //2 for type, 2 for class
	}

	int a;
	int got_answer=0;

	// now answer_ptr points at the first answer. loop through
	// all answers in all sections
	for(a=0;a<answer_count+auth_count+other_count;a++) {
		// first the name this answer is referring to 
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*)answer_ptr;
		answer_ptr+=sizeof(struct dns_rr);

		const uint8_t RECTYPE_A=1;
		const uint8_t RECTYPE_NS=2;
		const uint8_t RECTYPE_CNAME=5;
		const uint8_t RECTYPE_SOA=6;
		const uint8_t RECTYPE_PTR=12;
		const uint8_t RECTYPE_AAAA=28;

		if(htons(rr->type)==RECTYPE_A) {
                        if(debug) {
			printf("The name %s resolves to IP addr: %s\n",
						 string_name,
						 inet_ntoa(*((struct in_addr *)answer_ptr)));
                        }
                        // check if this was the hostname
                        if(strcmp(string_name, hostname) == 0) {
                            strcpy(address, inet_ntoa(*((struct in_addr *)answer_ptr)));
                            strcpy(name, string_name);
                          return 1;
                        }
                        a_records++;

                        // find correspinding ns and add ip
                        int index;
                        for(index=0; index < ns_records; index++) {
                          if( strcmp(ns_list[index][0], string_name) == 0) {
                            strcpy(ns_list[index][1], inet_ntoa(*((struct in_addr *)answer_ptr)));
                            break;
                          }
                        }
			got_answer=1;
		}
		// NS record
		else if(htons(rr->type)==RECTYPE_NS) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s can be resolved by NS: %s\n",
						 string_name, ns_string);
                        strcpy(ns_list[ns_records++][0], ns_string);					
			got_answer=1;
		}
		// CNAME record
		else if(htons(rr->type)==RECTYPE_CNAME) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s is also known as %s.\n",
						 string_name, ns_string);	
                        if(debug) printf("\n");
                        if (sendDnsQuery(ns_string, nameserver, address, name))
                          return 1;							
			got_answer=1;
		}
		// PTR record
		else if(htons(rr->type)==RECTYPE_PTR) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
                        if(debug)
			printf("The host at %s is also known as %s.\n",
						 string_name, ns_string);	
                        if(debug) printf("\n");
                        if (sendDnsQuery(ns_string, nameserver, address, name))
                          return 1;								
			got_answer=1;
		}
		// SOA record
		else if(htons(rr->type)==RECTYPE_SOA) {
			if(debug)
				printf("Ignoring SOA record\n");
		}
		// AAAA record
		else if(htons(rr->type)==RECTYPE_AAAA)  {
			if(debug)
				printf("Ignoring IPv6 record\n");
		}
		else {
			if(debug)
				printf("got unknown record type %hu\n",htons(rr->type));
		} 

		answer_ptr+=htons(rr->datalen);
	}
	
	//if(!got_answer) printf("Host %s not found.\n",argv[2]);
	
	shutdown(sock,SHUT_RDWR);
	close(sock);

	// first check name servers that have type a records

        int i;
        for(i=0; i<ns_records; i++) {
          if (ns_list[i][1][0] != 0) {
            if(debug)
              printf("\n");
            if(sendDnsQuery(hostname, ns_list[i][1], address, name))
              return 1;
            ns_list[i][0][0] = 0;
            ns_list[i][1][0] = 0;
          }
        }

        // the remaining name servers have no type A records, ask root servers
        for(i=0; i < ns_records;i++) {
          if(ns_list[i][0][0] != 0) {
            int k;
            char nsAddr[255];
            char nsName[255];
            memset(nsName, 0, 255);
            memset(nsAddr, 0, 255);
            // check each root server until the ip is found
            for(k=0; k < rs_count;k++) { 
              if(debug) printf("\n");
              if(sendDnsQuery(ns_list[i][0], rootServers[k], nsAddr, nsName)) {
 	        // ip found, and stored in nsAddr
                if(debug) printf("\n");
                if (sendDnsQuery(hostname, nsAddr, address, name)) 
                  return 1;
                break;
              }
            }
            ns_list[i][0][0] = 0;
          }
        }
  return 0;
} 

int isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main(int argc, char** argv)
{
  FILE *file;
  memset(rootServers, 0, 2000);
  char readBuff[255];
  char address[255];
  char name[255];
  memset(name,0,255);
  memset(address, 0, 255);

  if(argc<2) usage();
	
  char *hostname;
  char *nameserver;
	
  char *optString = "-d-n:-i:";
  int opt = getopt( argc, argv, optString );

    // get arguments
    while( opt != -1 ) {
        switch( opt ) {      
        	case 'd':
        		debug = 1; 
        		break;
        	case 'n':
        		nameserver_flag = 1; 
        		nameserver = optarg;
        		break;	 		
            case 'i':
                hostname = optarg;
                break;	
            case '?':
				usage();
        		exit(1);               
            default:
            	usage();
            	exit(1);
        }
        opt = getopt( argc, argv, optString );
    }
  
  file = fopen("root-servers.txt", "r");  
  
  // get the root servers from file
  while( fgets(readBuff, 255, file)) {
    int len = strlen(readBuff);
    readBuff[len-1] = 0;
    strcpy(rootServers[rs_count++], readBuff);
  }
  int ip = isValidIpAddress(hostname);

  if(nameserver_flag) {
    //use the nameserver provided
    int found = sendDnsQuery(hostname, nameserver, address, name);
    printf("%s resolves to %s\n", ip ? address : hostname, ip ? name : address);
    return 0;
  }
  else {
    // use root servers
    int i;
    for (i=0; i < rs_count; i++) {
      int found = sendDnsQuery(hostname, rootServers[i], address, name);
      if (found) {
        printf("%s resolves to %s\n", ip ? address : hostname, ip ? name : address);
        return 0;
      }
    }
    printf("hostname could not be resolved\n");
  }
}
