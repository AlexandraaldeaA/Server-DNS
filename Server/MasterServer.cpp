#include "dns.h"

void dig_dns_request(int,int,int,unsigned char*,sockaddr_in,socklen_t);
int verify_cache(int,unsigned char*,int,sockaddr_in,socklen_t);
void add_cache(unsigned char*, struct RES_RECORD*, int);
int verify_master_file(int,sockaddr_in,socklen_t,unsigned char*,int);
void add_from_zone_file( struct RES_RECORD*, unsigned char*,bool);
void update_cache_timers();
void change_dns_format_name(unsigned char*,unsigned char*);
void forward_dns_request(int, int, sockaddr_in, socklen_t, unsigned char*);
bool is_plain_text_domain(const unsigned char*, int);
unsigned char* read_name(unsigned char*,unsigned char*,int*);

int main() 
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); //UDP

    if (sockfd < 0) 
    {
        std::cerr << "Failed to create socket" << std::endl;
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        std::cerr << "Bind failed" << std::endl;
        close(sockfd);
        return EXIT_FAILURE;
    }

    int google_sockfd = socket(AF_INET, SOCK_DGRAM, 0); //UDP

    if (google_sockfd < 0) 
    {
        std::cerr << "Failed to create Google DNS socket" << std::endl;
        close(sockfd);
        return EXIT_FAILURE;
    }

    std::cout << "DNS server started..." << std::endl;

    unsigned char* buffer=(unsigned char*)malloc(sizeof(unsigned char)*BUFFER_SIZE); 

    struct timeval timeout;
    fd_set readfds;

    while (true) 
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) 
        {
            std::cerr << "Eroare la select" << std::endl;
            exit(EXIT_FAILURE);
        } 
        else if (activity == 0) 
        {
            //no activity on socket
            update_cache_timers();
        } 
        else 
        {
            if (FD_ISSET(sockfd, &readfds))
            {
                memset(buffer, 0, sizeof(buffer));
                struct sockaddr_in client;
                socklen_t client_len = sizeof(client);

                int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client, &client_len);

                buffer[strlen((char*)(buffer))-1]='\0';

                std::cout<<buffer<<std::endl;

                if (n < 0) 
                {
                    std::cerr << "recvfrom failed" << std::endl;
                    exit(EXIT_FAILURE);
                }

                if(is_plain_text_domain(buffer, n)==0)
                {
                    dig_dns_request(sockfd,google_sockfd,n,buffer,client,client_len);
                }
                else
                {
                    if(verify_cache(sockfd,buffer,n,client,client_len)==0)
                    {
                        if(verify_master_file(sockfd,client,client_len,buffer,n)==0)
                        {
                            forward_dns_request(sockfd,google_sockfd,client,client_len,buffer);
                        }
                    }
                }
            }
        }
    }
    close(sockfd);
    close(google_sockfd);
    return 0;
}

void dig_dns_request(int sockfd, int google_sockfd, int n, unsigned char* buffer,sockaddr_in client,socklen_t client_len) 
{
    std::cout<<"dig"<<std::endl;
    std::cout<<"Received from client: "<<buffer<<std::endl;

    DNS_HEADER *dns = (DNS_HEADER*)buffer;
    std::cout << "Received DNS query with ID: " << ntohs(dns->id) << std::endl;

    struct sockaddr_in google_dns;
    google_dns.sin_family = AF_INET;
    google_dns.sin_port = htons(GOOGLE_DNS_PORT);
    google_dns.sin_addr.s_addr = inet_addr(GOOGLE_DNS);

    if (sendto(google_sockfd, buffer, n, 0, reinterpret_cast<struct sockaddr *>(&google_dns), sizeof(google_dns)) < 0) 
    {
        std::cerr << "Failed to send to Google DNS" << std::endl;
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in google_response_addr;
    socklen_t google_addr_len = sizeof(google_response_addr);

    n = recvfrom(google_sockfd, buffer, BUFFER_SIZE, 0, reinterpret_cast<struct sockaddr *>(&google_response_addr), &google_addr_len);
    if (n < 0) 
    {
        std::cerr << "recvfrom failed (Google DNS)" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (sendto(sockfd, buffer, n, 0, reinterpret_cast<struct sockaddr *>(&client), client_len) < 0) 
    {
        std::cerr << "Failed to send response to client" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "DNS response sent to client" << std::endl;
}

int verify_cache(int sockfd,unsigned char* domain_name,int n,sockaddr_in client,socklen_t client_len)
{
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    for(int i=0;i<size(cache);i++)
    {
        if (strcmp((char*)domain_name, (char*)cache[i].domain_name) == 0)
        {
            std::cout<<"cache"<<std::endl;
            cache[i].timer=86400;
        
            strcat((char*)buffer,"Non_Authoritative");
            strcat((char*)buffer,"\n");
            strcat((char*)buffer,"Name: ");
            strcat((char*)buffer,(char*)cache[i].domain_name);
            strcat((char*)buffer,"\n");
            strcat((char*)buffer,"Adress: ");
            strcat((char*)buffer,(char*)cache[i].ip_address);
            strcat((char*) buffer,"\0");
            strcat((char*) buffer,"\n");

            size_t length = strlen(reinterpret_cast<const char*>(buffer));

            if (sendto(sockfd, buffer, length, 0, reinterpret_cast<struct sockaddr *>(&client), client_len) < 0) 
            {
                std::cerr << "Failed to send response to client" << std::endl;
                exit(EXIT_FAILURE);
            }
            return 1;
        }
    }
    return 0;
}

int verify_master_file(int sockfd,sockaddr_in client,socklen_t client_len,unsigned char* domain_name,int n)
{
    bool ok=0;

    std::ifstream file("MasterFile"); 
    if (!file.is_open()) {
        std::cerr << "Error opening MasterFile" << std::endl;
        return -1;
    }

    unsigned char* processed_name=(unsigned char*)malloc(sizeof(unsigned char)*100);

    if (strncmp((char*)domain_name, "www.", 4) == 0) {
        strcpy((char*)processed_name, (char*)domain_name + 4); 
        ok = 1;
    } else 
    {
        strcpy((char*)processed_name, (char*)domain_name); 
        ok = 0;
    }

    std::string str_processed_name((char*)processed_name);
    std::string line;

    std::string line_to_find = "zone \"" + str_processed_name + "\"";

    while(std::getline(file,line))
    {   
        if (line==line_to_find) 
        {
            std::cout<<"masterFile"<<std::endl;

            unsigned char response[BUFFER_SIZE];
            memset(response, 0, BUFFER_SIZE);

            DNS_HEADER *dns_response = (DNS_HEADER*)response;

            unsigned char* qname_response=(unsigned char*)&response[sizeof(struct DNS_HEADER)];

            strcpy((char*)qname_response,(char*)domain_name);

            QUESTION* qinfo_response =(struct QUESTION*)&response[sizeof(struct DNS_HEADER) + (strlen((const char*)qname_response) + 1)];
            qinfo_response->qclass=htons(1);
            qinfo_response->qtype=htons(1); //IPv4 -----

            struct RES_RECORD* answer=(struct RES_RECORD*)&response[sizeof(struct DNS_HEADER)+strlen((char*)domain_name)+1+sizeof(struct QUESTION)];

            add_from_zone_file(answer,processed_name,ok);

            add_cache(domain_name,answer,0);

            unsigned char client_buffer[BUFFER_SIZE];
            memset(client_buffer, 0, sizeof(client_buffer));

            strcat((char*)client_buffer,"Authoritative");
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Name: ");
            strcat((char*)client_buffer,(char*)domain_name);
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Adress: ");
            strcat((char*)client_buffer,(char*)answer->rdata);
            strcat((char*) client_buffer,"\0");
            strcat((char*) client_buffer,"\n");

            size_t length = strlen(reinterpret_cast<const char*>(client_buffer));

            if (sendto(sockfd, client_buffer, length, 0, reinterpret_cast<struct sockaddr *>(&client), client_len) < 0) 
            {
                std::cerr << "Failed to send response to client" << std::endl;
                exit(EXIT_FAILURE);
            }
            return 1;
            }
        }
    file.close();
    free(processed_name);
    return 0;
}                               

void add_from_zone_file( struct RES_RECORD* answer, unsigned char* qname,bool ok)
{

    answer->resource = (struct R_DATA*)malloc(sizeof(struct R_DATA));

    answer->name=(unsigned char*)malloc(sizeof(unsigned char)*strlen((char*)qname));
    strcpy((char*)answer->name,(char*)qname);

    std::ifstream file((char*)qname); 
    if (!file.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    
    //doar pentru ipv4 doecamdata
    std::string line;

    while(std::getline(file,line))
    {
        if (line.find("$TTL") != std::string::npos) 
        {
            std::istringstream iss(line);
            std::string ttl_token;
            int value;

            iss >> ttl_token;
            iss >> value;

            answer->resource->ttl=htonl((int32_t)value);
            answer->resource->type=htons(1);
            answer->resource->_class=htons(1);
        }

        if (ok==1)
        {
           if (line.find(" A ") != std::string::npos && line.find("@") != std::string::npos)
           {
                std::istringstream iss(line);
                std::string token;
                iss >> token;
                iss >> token;
                iss >> token;
                iss >> token;

                answer->rdata=(unsigned char*)malloc(sizeof(unsigned char)*50);
                strcpy((char*)answer->rdata,token.c_str());
                answer->resource->data_len=htons(4);

           } 
        }   
    }
    file.close();
}

void add_cache(unsigned char* domain_name,struct RES_RECORD* answer,int from_forward)
{
    
    CACHE entry;
    entry.domain_name=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)domain_name)+1));
    entry.ip_address=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)answer->rdata)+1));

    
    strcpy((char*)entry.domain_name,(char*)domain_name);

    if(from_forward==0)
    {
        strcpy((char*)entry.ip_address,(char*)answer->rdata);
        entry.type=answer->resource->type;
        entry.timer=86400;
    }
    else
    {
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, answer->rdata, ipv4, INET_ADDRSTRLEN);
        strcpy((char*)entry.ip_address,ipv4);
        entry.timer=86400;
        entry.type=ntohs(answer->resource->type);
    }

    cache.push_back(entry);
}

void update_cache_timers() 
{
    auto it = cache.begin();
    while (it != cache.end()) 
    {
        it->timer--;
        std::cout<<it->domain_name<<":"<<it->timer<<std::endl;

        if (it->timer <= 0)
        {
            delete it->domain_name;
            delete it->ip_address;

            it = cache.erase(it);
            std::cout << "Cache entry expired and removed" << std::endl;
        }
        else 
        {
            ++it;
        }
    }
}

void forward_dns_request(int sockfd, int google_sockfd, sockaddr_in client, socklen_t client_len, unsigned char* domain_name)
{
    std::cout<<"forward"<<std::endl;
    unsigned char buf[BUFFER_SIZE],*name,*reader;
    memset(buf,0,sizeof(buf));

	struct DNS_HEADER *dns = NULL;
    dns = (struct DNS_HEADER *)&buf;
	struct QUESTION *qinfo = NULL;
    struct RES_RECORD answers[20];

    struct sockaddr_in google_dns;
    google_dns.sin_family = AF_INET;
    google_dns.sin_port = htons(GOOGLE_DNS_PORT);
    google_dns.sin_addr.s_addr = inet_addr(GOOGLE_DNS);

    dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //query
	dns->opcode = 0; //standard query
	dns->aa = 0; //not authoritative
	dns->tc = 0; //not truncated
	dns->rd = 1; //recursion desired
	dns->ra = 0; //recursion not available
	dns->z = 0;
	dns->ad = 1;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = htons(1);

    name =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

    change_dns_format_name(name , domain_name);

    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1)];

    qinfo->qtype = htons(1);
	qinfo->qclass = htons(1); //clasa IN(internet)

    if (sendto(google_sockfd, buf, BUFFER_SIZE, 0, (struct sockaddr *)&google_dns, sizeof(google_dns)) < 0) 
    {
        std::cerr << "Failed to send to Google DNS" << std::endl;
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in google_response_addr;
    socklen_t google_addr_len = sizeof(google_response_addr);

    if(recvfrom(google_sockfd, buf, BUFFER_SIZE, 0, (struct sockaddr *)&google_response_addr, &google_addr_len)< 0) 
    {
        std::cerr << "recvfrom failed (Google DNS)" << std::endl;
        exit(EXIT_FAILURE);
    }

    dns = (struct DNS_HEADER*) buf;

    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)name)+1) + sizeof(struct QUESTION)];

    //read answers
    int stop=0;
    unsigned char client_buffer[BUFFER_SIZE];
    memset(client_buffer, 0, sizeof(client_buffer));

    for(int i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=(unsigned char*)malloc(1000);
        answers[i].name=read_name(reader,buf,&stop);

        std::cout<<answers[i].name<<std::endl;
        
        reader = reader + stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader=reader+sizeof(struct R_DATA);

        if(ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

            for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);

            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, answers[0].rdata, ipv4, INET_ADDRSTRLEN);

            add_cache(answers[i].name,&answers[i],1);

            strcat((char*)client_buffer,"Non-Authoritative");
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Name: ");
            strcat((char*)client_buffer,(char*)answers[i].name);
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Adress: ");
            strcat((char*)client_buffer,ipv4);
            strcat((char*) client_buffer,"\0");
            strcat((char*) client_buffer,"\n");
        }
    }

    size_t length = strlen((const char*)client_buffer);

    if (sendto(sockfd, client_buffer, length, 0, (struct sockaddr *)&client, client_len) < 0) 
    {
        std::cerr << "Failed to send response to client" << std::endl;
        exit(EXIT_FAILURE);
    }
}

void change_dns_format_name(unsigned char * dns, unsigned char* domain_name)
{
    strcat((char*)domain_name, ".");
    int pos=0;
    for(int i=0;i<strlen((char*)domain_name);i++)
    {
        if(domain_name[i]=='.')
        {
           *dns++ = i - pos;
            for(int j=pos;j<i;j++)
            {
                *dns++=domain_name[j];
                pos++;
            }
            pos++;
        }
    }
    *dns++='\0'; //3www3mta2ro
}

bool is_plain_text_domain(const unsigned char* buffer, int n) 
{
    // Verificăm dacă bufferul conține doar caractere ASCII eligibile pentru un domeniu
    for (int i = 0; i < n && buffer[i] != '\0'; ++i) {
        if (!std::isalnum(buffer[i]) && buffer[i] != '.' && buffer[i] != '-') {
            return false;  // Dacă găsim un caracter neeligibil, nu e cerere simplă
        }
    }
    return true;
}

unsigned char* read_name(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;

    *count = 1;

    name = (unsigned char*)malloc(256);

    name[0]='\0';

    while(*reader!=0) //till we arrived to the end of the codified name
    {
        if(*reader>=192) //check if compression label; used for compression label(uses 2 bytes to refer to the location  of the already used name and points to the location)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //0b11000000xxxxxxxx 
            //*reader =11000000 in the first 2 bits and the rest 6 bits for the offset -the first octet
            //*reader+1 =the second octet
            //*reader*256 =left shift with 8 bits
            //49152=11000000 00000000
            //ex:*reader=192, *reader+1=12=>192*256=49152; 49152+12=49164; 49164-49152=12(the real offset)=>pos 12 in buffer

            reader = buffer + offset - 1;

            jumped = 1; //jumped to another location
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
		{
			*count = *count + 1; //we havent jumped to another location so we can add to the count
		}
    }

    name[p]='\0';

    if(jumped==1)
	{
		*count = *count + 1; 
	}

    int i;
    int contor=0;

    unsigned char* new_name;
    new_name = (unsigned char*)malloc(1000);
    new_name[0] = '\0';

    for (i = 0; i < strlen((const char*)name); i++)
	{
		p = name[i];
		for (int j = 0; j < p; j++)
		{
			new_name[contor] = name[i + 1];
			i = i + 1;
			contor++;
		}
		new_name[contor] = '.';
		contor++;
	}
	new_name[contor-1] = '\0';

    free(name);
	return new_name;
}