#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
 
// Lista de servidores DNS registados
char dns_servers[10][100];

// Tipos de DNS Resource Records
#define T_A 1		// Endereço Ipv4
#define T_NS 2		// Nameserver
#define T_CNAME 5 	// Canonical Name
#define T_SOA 6 	// Authority zone
#define T_PTR 12 	// Domain name pointer
#define T_MX 15 	// Mail server
 
// Declaração das Funções
void ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();
 
// Estrutura de um DNS Header
struct DNS_HEADER
{
    unsigned short id; // ID Number
 
    unsigned char rd :1; 		// Recursividade desejada
    unsigned char tc :1; 		// Mensagem truncada
    unsigned char aa :1; 		// Resposta Autoritativa
    unsigned char opcode :4;	// Propósito da Mensagem
    unsigned char qr :1; 		// Query/Response flag
 
    unsigned char rcode :4; 	// Código de Resposta
    unsigned char cd :1; 		// 'Checking' desativado
    unsigned char ad :1; 		// Data autenticada
    unsigned char z :1;
    unsigned char ra :1; 		// Recursividade Disponível
 
    unsigned short q_count; 	// Número de Perguntas
    unsigned short ans_count; 	// Número de Respostas
    unsigned short auth_count;	// Número de entradas Autoritativas
    unsigned short add_count; 	// Número de entradas dos Recursos
};
 
// Estrutura da Query
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
// Estrutura dos Resource Records
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
// Apontadores para os conteúdos dos Resource Records
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
// Apontadores da Estrutura da Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;
 
int main( int argc , char *argv[])
{
    unsigned char hostname[100];
 
    // GET dos servidores DNS
    get_dns_servers();
     
    // GET do hostname a partir do terminal
    printf("Introduza um hostname: ");
    scanf("%s" , hostname);
     
    // GET do IP do hostname
    ngethostbyname(hostname , T_A);
 
    return 0;
}
 
// Esta função executa uma DNS Query ao enviar um 'packet'
void ngethostbyname(unsigned char *host , int query_type)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
 
    struct sockaddr_in a;
 
    struct RES_RECORD answers[20],auth[20],addit[20];
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    printf("Resolving %s" , host);
 
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
 
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
 
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    // Apontador para uma porção da Query
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
 
    qinfo->qtype = htons( query_type ); // Tipo de Query (A , MX , CNAME , NS, etc...)
    qinfo->qclass = htons(1);
	
	// Envia a pergunta
    printf("\nEnviando pergunta...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto falhado.");
    }
    printf("Feito!");
     
    // Recebe a resposta
    i = sizeof dest;
    printf("\nRecebendo resposta...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom falhado.");
    }
    printf("Feito!");
 
    dns = (struct DNS_HEADER*) buf;
 
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nA resposta contem: ");
    printf("\n %d Questoes.",ntohs(dns->q_count));
    printf("\n %d Respostas.",ntohs(dns->ans_count));
    printf("\n %d Servidores autoritativos.",ntohs(dns->auth_count));
    printf("\n %d Registos adicionais.\n\n",ntohs(dns->add_count));
 
    // Começar a ler as respostas
    stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1)
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
 
    // Read das Authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    // Read adicional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
 
    // Print das respostas
    printf("\nRegistos da resposta: %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("Nome: %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A)
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("Tem o endereço IPv4: %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            printf("Tem o alias: %s",answers[i].rdata);
        }
 
        printf("\n");
    }
 
    // Print dos Servidores Autoritativos
    printf("\nRegistos autoritativos: %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
         
        printf("Nome: %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            printf("tem o nameserver: %s",auth[i].rdata);
        }
        printf("\n");
    }
 
    // Print dos Registos Adicionais
    printf("\nRegistos adicionais: %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        printf("Nome: %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("tem o endereco IPv4: %s",inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return;
}
 
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    // Leitura dos nomes no formato '3www6google3com'
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1)
    {
        *count = *count + 1;
    }
 
    // Converter '3www6google3com0' em 'www.google.com'
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}
 
// Esta função recebe os servidores DNS (hardcoded)
void get_dns_servers()
{ 
    strcpy(dns_servers[0] , "8.8.8.8"); 	//Para usar fora da universidade (Google DNS)
    strcpy(dns_servers[1] , "10.1.80.110"); //Para usar na universidade
}
 

// Esta função converte um hostname, como 'www.google.com' em '3www6google3com'
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}