#include "dns.h"

void dig_dns_request(int,int,int,unsigned char*,sockaddr_in,socklen_t);
int verify_cache(int,unsigned char*,int,sockaddr_in,socklen_t,int);
void add_cache(unsigned char*,struct RES_RECORD*,int);
bool verify_master_file(int,sockaddr_in,socklen_t,unsigned char*,int,int);
void add_from_zone_file(struct RES_RECORD*,unsigned char*,bool,int);
void update_cache_timers();
void change_dns_format_name(unsigned char*,unsigned char*);
void forward_dns_request(int,int,sockaddr_in,socklen_t,unsigned char*,int);
bool is_plain_text_domain(const unsigned char*,int);
unsigned char* read_name(unsigned char*,unsigned char*,int*);
void reverse_dns_request(int,int,sockaddr_in,socklen_t,char*);
bool verify_reverse_file(char*,char*);
void handle_dns_request(int,int,sockaddr_in,socklen_t,unsigned char*,int);
void add_edns_section(unsigned char*,int*);
void init_log_file(std::ofstream&);
void log_message(const std::string&,std::ofstream&);

int main() 
{
    init_log_file(logFile);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); //UDP

    if (sockfd < 0)
    {
        log_message("Failed to create socket!", logFile);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
    {
        log_message("Bind failed!", logFile);
        close(sockfd);
        return EXIT_FAILURE;
    }

    int google_sockfd = socket(AF_INET, SOCK_DGRAM, 0); //UDP

    if (google_sockfd < 0) 
    {
        log_message("Failed to create Google DNS socket!", logFile);
        close(sockfd);
        return EXIT_FAILURE;
    }

    log_message("DNS Server started...", logFile);

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
            log_message("Select failed!", logFile);
            exit(EXIT_FAILURE);
        } 
        else if (activity == 0) 
        {
            std::cout<<"aici"<<std::endl;
            update_cache_timers();
        } 
        else 
        {
            if (FD_ISSET(sockfd, &readfds))
            {
                memset(buffer, 0, BUFFER_SIZE);
                struct sockaddr_in client;
                socklen_t client_len = sizeof(client);

                int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client, &client_len);

                std::cout<<"after recv"<<std::endl;

                buffer[strlen((char*)(buffer))-1]='\0';

                std::cout<<buffer<<std::endl;

                if (n < 0) 
                {
                    log_message("Recvfrom failed!", logFile);
                    exit(EXIT_FAILURE);
                }

                handle_dns_request(sockfd,google_sockfd,client,client_len,buffer,n);
                std::cout<<"finished"<<std::endl;
            }
        }
    }

    close(sockfd);
    close(google_sockfd);
    logFile.close();
    return 0;
}

void dig_dns_request(int sockfd, int google_sockfd, int n, unsigned char* buffer,sockaddr_in client,socklen_t client_len) 
{
    std::cout<<"dig"<<std::endl;
    log_message("DIG request", logFile);
    std::cout<<"Received from client: "<<buffer<<std::endl;

    DNS_HEADER* dns = (DNS_HEADER*)buffer;
    std::cout << "Received DNS query with ID: " << ntohs(dns->id) << std::endl;

    struct sockaddr_in google_dns;
    google_dns.sin_family = AF_INET;
    google_dns.sin_port = htons(GOOGLE_DNS_PORT);
    google_dns.sin_addr.s_addr = inet_addr(GOOGLE_DNS);

    if (sendto(google_sockfd, buffer, n, 0, reinterpret_cast<struct sockaddr *>(&google_dns), sizeof(google_dns)) < 0) 
    {
        log_message("Failed to send to Google DNS!", logFile);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in google_response_addr;
    socklen_t google_addr_len = sizeof(google_response_addr);

    n = recvfrom(google_sockfd, buffer, BUFFER_SIZE, 0, reinterpret_cast<struct sockaddr *>(&google_response_addr), &google_addr_len);
    if (n < 0) 
    {
        log_message("Recvfrom failed (Google DNS)!", logFile);
        exit(EXIT_FAILURE);
    }

    if (sendto(sockfd, buffer, n, 0, reinterpret_cast<struct sockaddr *>(&client), client_len) < 0) 
    {
        log_message("Failed to send response to client!", logFile);
        exit(EXIT_FAILURE);
    }

    std::cout << "DNS response sent to client" << std::endl;
    log_message("DNS response sent to client!", logFile);
}

int verify_cache(int sockfd,unsigned char* domain_name,int n,sockaddr_in client,socklen_t client_len,int qtype)
{
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    for(int i=0;i<cache.size();i++)
    {
        if ((cache[i].domain_name && strcmp((char*)domain_name, (char*)cache[i].domain_name) == 0) || (cache[i].resolved_name && strcmp((char*)domain_name, (char*)cache[i].resolved_name) == 0))
        {
            if(cache[i].type==qtype)
            {
                std::cout<<"cache"<<std::endl;
                cache[i].timer=86400;
        
                strcat((char*)buffer,"Authoritative");
                strcat((char*)buffer,"\n");
                strcat((char*)buffer,"Name: ");
                strcat((char*)buffer,(char*)domain_name);
                strcat((char*)buffer,"\n");
                strcat((char*)buffer,"Answer Section: ");
                if(cache[i].ip_address)
                    strcat((char*)buffer,(char*)cache[i].ip_address);
                else if(cache[i].reverse_ip)
                    strcat((char*)buffer,(char*)cache[i].reverse_ip);
                strcat((char*) buffer,"\0");
                strcat((char*) buffer,"\n");

                size_t length = strlen(reinterpret_cast<const char*>(buffer));
                log_message("From cache.", logFile);

                if (sendto(sockfd, buffer, length, 0, reinterpret_cast<struct sockaddr*>(&client), client_len) < 0) 
                {
                    log_message("Failed to send response to client!", logFile);
                    exit(EXIT_FAILURE);
                }
                return 1;
            }
        }
    }
    return 0;
}

bool verify_master_file(int sockfd,sockaddr_in client,socklen_t client_len,unsigned char* domain_name,int n,int qtype)
{
    bool ok=0;

    std::ifstream file("MasterFile");
    if (!file.is_open()) 
    {
        log_message("Error opening MasterFile!", logFile);
        return -1;
    }

    unsigned char* processed_name=(unsigned char*)malloc(sizeof(unsigned char)*100);

    if (strncmp((char*)domain_name, "www.", 4) == 0) 
    {
        strcpy((char*)processed_name, (char*)domain_name + 4); 
        ok = 1;
    } 
    else 
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

            DNS_HEADER* dns_response = (DNS_HEADER*)response;

            unsigned char* qname_response=(unsigned char*)&response[sizeof(struct DNS_HEADER)];

            strcpy((char*)qname_response,(char*)domain_name);

            QUESTION* qinfo_response =(struct QUESTION*)&response[sizeof(struct DNS_HEADER) + (strlen((const char*)qname_response) + 1)];
            qinfo_response->qclass=qtype;
            qinfo_response->qtype=1; 

            struct RES_RECORD* answer=(struct RES_RECORD*)&response[sizeof(struct DNS_HEADER)+strlen((char*)domain_name)+1+sizeof(struct QUESTION)];

            add_from_zone_file(answer,processed_name,ok,qtype);

            log_message("From MasterFile.", logFile);
            add_cache(domain_name,answer,0);

            unsigned char client_buffer[BUFFER_SIZE];
            memset(client_buffer, 0, sizeof(client_buffer));

            strcat((char*)client_buffer,"Authoritative");
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Name: ");
            strcat((char*)client_buffer,(char*)domain_name);
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Answer Section: ");
            strcat((char*)client_buffer,(char*)answer->rdata);
            strcat((char*) client_buffer,"\0");
            strcat((char*) client_buffer,"\n");

            size_t length = strlen(reinterpret_cast<const char*>(client_buffer));

            if (sendto(sockfd, client_buffer, length, 0, reinterpret_cast<struct sockaddr*>(&client), client_len) < 0) 
            {
                log_message("Failed to send response to client!", logFile);
                exit(EXIT_FAILURE);
            }
            return 1;
            }
        }

    file.close();
    free(processed_name);
    return 0;
}                               

void add_from_zone_file( struct RES_RECORD* answer, unsigned char* qname,bool ok,int qtype)
{
    answer->resource = (struct R_DATA*)malloc(sizeof(struct R_DATA));

    answer->name=(unsigned char*)malloc(sizeof(unsigned char)*strlen((char*)qname));
    strcpy((char*)answer->name,(char*)qname);

    std::ifstream file((char*)qname); 
    if (!file.is_open()) 
    {
        log_message("Error opening file!", logFile);
        return;
    }

    int found_NS=0;
    
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

            answer->resource->ttl=(int32_t)value;
            answer->resource->type=qtype;
            answer->resource->_class=1;
        }

        if (qtype==1) 
        {
            if(ok==1) //name with www at first
            {
                if (line.find(" A ") != std::string::npos && line.find("www") != std::string::npos)
                {
                    std::istringstream iss(line);
                    std::string token;
                    iss >> token;
                    iss >> token;
                    iss >> token;
                    iss >> token;

                    answer->rdata=(unsigned char*)malloc(sizeof(unsigned char)*50);
                    strcpy((char*)answer->rdata,token.c_str());
                    answer->resource->data_len=4;

                } 
           }
           else if(ok==0) //name without www at first
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
                    answer->resource->data_len=4;

                }
           }
        }
        else if(qtype==28)
        {
            if (line.find(" AAAA ") != std::string::npos && line.find("@") != std::string::npos)
            {
                std::istringstream iss(line);
                std::string token;
                iss >> token;
                iss >> token;
                iss >> token;
                iss >> token;

                answer->rdata=(unsigned char*)malloc(sizeof(unsigned char)*50);
                strcpy((char*)answer->rdata,token.c_str());
                answer->resource->data_len=16;

            } 
        }
        else if(qtype==15)
        {
            if (line.find(" MX ") != std::string::npos && line.find("@") != std::string::npos)
            {
                std::istringstream iss(line);
                std::string token;
                iss >> token;
                iss >> token;
                iss >> token;
                iss >> token;

                answer->rdata=(unsigned char*)malloc(sizeof(unsigned char)*50);
                strcpy((char*)answer->rdata,token.c_str());
                answer->resource->data_len=256;
            }
        }
        else if(qtype==2)
        {
            if (line.find(" NS ") != std::string::npos && line.find("@") != std::string::npos)
            {
                std::istringstream iss(line);
                std::string token;
                iss >> token;
                iss >> token;
                iss >> token;
                iss >> token;

                if(found_NS==0)
                {
                    answer->rdata=(unsigned char*)malloc(sizeof(unsigned char)*1000);
                    strcpy((char*)answer->rdata,token.c_str());
                    answer->resource->data_len=256;
                    found_NS++;
                }
                else
                {
                    strcat((char*)answer->rdata," ");
                    strcat((char*)answer->rdata,token.c_str());
                }

            }
        }
    }
    file.close();
}

void add_cache(unsigned char* domain_name,struct RES_RECORD* answer,int from_forward)
{
    CACHE entry;
    std::cout<<strlen((char*)domain_name)<<std::endl;

    entry.domain_name = (unsigned char*)malloc((strlen((char*)domain_name) +1)*sizeof(unsigned char));
    entry.ip_address=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)answer->rdata)+1));
    entry.resolved_name=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)domain_name)+1));
    entry.reverse_ip=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)answer->rdata)+1));

    entry.timer=86400;

    if(strcmp((char*)answer->rdata,"0")==0)
    {
        return;
    }
    else if(from_forward==1 && ntohs(answer->resource->type)==1)
    {
        strcpy((char*)entry.domain_name,(char*)domain_name);
        std::cout<<"1 1"<<std::endl;
        strcpy((char*)entry.ip_address,(char*)answer->rdata);
        entry.type=ntohs(answer->resource->type);
        entry.reverse_ip = nullptr;  
        entry.resolved_name = nullptr;
    }
    else if(from_forward==1 && ntohs(answer->resource->type)==28)
    {
        strcpy((char*)entry.domain_name,(char*)domain_name);
        strcpy((char*)entry.ip_address,(char*)answer->rdata);
        entry.type=ntohs(answer->resource->type);
        entry.reverse_ip = nullptr; 
        entry.resolved_name = nullptr;
    }
    else if(from_forward==0 && strcmp((char*)answer->rdata,"0") && answer->resource->type!=12)
    {
        strcpy((char*)entry.domain_name,(char*)domain_name);
        strcpy((char*)entry.ip_address,(char*)answer->rdata);
        entry.type=answer->resource->type;
        entry.reverse_ip = nullptr;  
        entry.resolved_name = nullptr;
    }
    else
    {
        std::cout<<"0 sau 1 12"<<std::endl;
        entry.domain_name=nullptr;
        entry.ip_address=nullptr;
        strcpy((char*)entry.resolved_name,(char*)domain_name);
        strcpy((char*)entry.reverse_ip,(char*)answer->rdata);
        if(from_forward==1)
            entry.type=ntohs(answer->resource->type);
        else    
            entry.type=answer->resource->type;
    }

    if(cache.size()==LIMIT_CACHE)
    {
        auto it_to_remove = cache.begin();
        int min_timer = it_to_remove->timer;

        for (auto it = cache.begin(); it != cache.end(); ++it) 
        {
            if (it->timer < min_timer) 
            {
                min_timer = it->timer;
                it_to_remove = it;
            }
        }

        std::ostringstream log1;
        if(it_to_remove->domain_name==nullptr)
            log1 << "Removed from cache: " << it_to_remove->resolved_name;
        else
            log1 << "Removed from cache: " << it_to_remove->domain_name;
        log_message(log1.str(), logFile);
        free(it_to_remove->domain_name);
        free( it_to_remove->ip_address);

        if (it_to_remove->reverse_ip) 
            free( it_to_remove->reverse_ip);
        if (it_to_remove->resolved_name) 
            free( it_to_remove->resolved_name);

        cache.erase(it_to_remove);
        cache.push_back(entry);
        std::ostringstream log3;
        if(entry.domain_name==nullptr)
            log3 << "Added to cache: " << entry.resolved_name;
        else   
            log3 << "Added to cache: " << domain_name;
        log_message(log3.str(), logFile);
    }
    else
    {
        cache.push_back(entry);
        std::ostringstream log2;
        if(entry.domain_name==nullptr)
            log2 << "Added to cache: " << entry.resolved_name;
        else   
            log2 << "Added to cache: " << domain_name;
        log_message(log2.str(), logFile);
    }
    std::cout<<cache.size()<<std::endl;
}

void update_cache_timers() 
{
    auto it = cache.begin();
    while (it != cache.end()) 
    {
        it->timer--;
        if (it->domain_name != nullptr) 
        {
            std::cout << it->domain_name << ":" << it->timer << std::endl;
        } 
        else if (it->resolved_name != nullptr) 
        {
            std::cout << it->resolved_name << ":" << it->timer << std::endl;
        } 
        else 
        {
            std::cout << "Unknown entry: " << it->timer << std::endl;
        }

        if (it->timer <= 0)
        {
            free(it->domain_name);
            free(it->ip_address);

            it = cache.erase(it);
            log_message("Cache entry expired and removed.", logFile);
            std::cout << "Cache entry expired and removed." << std::endl;
        }
        else 
        {
            ++it;
        }
    }
}

void forward_dns_request(int sockfd, int google_sockfd, sockaddr_in client, socklen_t client_len, unsigned char* domain_name, int qtype)
{
    std::cout<<"forward"<<std::endl;
    log_message("Forwarding.", logFile);
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

    qinfo->qtype = htons(qtype);
	qinfo->qclass = htons(1); //clasa IN(internet)

    int offset = sizeof(struct DNS_HEADER) + (strlen((const char*)name) + 1) + sizeof(struct QUESTION);
    add_edns_section(buf, &offset); //to remain modified

    if (sendto(google_sockfd, buf, BUFFER_SIZE, 0, (struct sockaddr *)&google_dns, sizeof(google_dns)) < 0) 
    {
        log_message("Failed to send to Google DNS!", logFile);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in google_response_addr;
    socklen_t google_addr_len = sizeof(google_response_addr);

    if(recvfrom(google_sockfd, buf, BUFFER_SIZE, 0, (struct sockaddr *)&google_response_addr, &google_addr_len)< 0) 
    {
        log_message("Recvfrom failed (Google DNS)!", logFile);
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
        answers[i].name=(unsigned char*)malloc(256);
        memset(answers[i].name,0,256);
        answers[i].name=read_name(reader,buf,&stop);
        
        reader += stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        if(i==1 && ntohs(answers[i-1].resource->type)==5)
        {
            memset(answers[i].name,0,256);
            strcpy((char*)answers[i].name,(char*)answers[i-1].name);
        }

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
            strcpy((char*)answers[i].rdata,ipv4);

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
        else if(ntohs(answers[i].resource->type) == 28)
        {
            answers[i].rdata = (unsigned char*)malloc(INET6_ADDRSTRLEN);
            for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader += ntohs(answers[i].resource->data_len);

            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, answers[i].rdata, ipv6, INET6_ADDRSTRLEN);
            strcpy((char*)answers[i].rdata,ipv6);

            add_cache(answers[i].name,&answers[i],1);

            strcat((char*)client_buffer,"Non-Authoritative");
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Name: ");
            strcat((char*)client_buffer,(char*)answers[i].name);
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Adress: ");
            strcat((char*)client_buffer,ipv6);
            strcat((char*) client_buffer,"\0");
            strcat((char*) client_buffer,"\n");
        }
        else if(ntohs(answers[i].resource->type) == 12) // PTR record
        {
            answers[i].rdata = read_name(reader, buf, &stop);
            reader += stop;

            unsigned char* temp=(unsigned char*)malloc(sizeof(unsigned char)*(strlen((char*)answers[i].name)+1));
            memset(temp,0,strlen((char*)answers[i].name));
            strcpy((char*)temp,(char*)answers[i].name);
            memset(answers[i].name,0,256);
            strcpy((char*)answers[i].name,(char*)answers[i].rdata);
            memset(answers[i].rdata,0,strlen((char*)answers[i].rdata));
            strcpy((char*)answers[i].rdata,(char*)temp);

            free(temp);

            add_cache(answers[i].name,&answers[i],1);

            strcat((char*)client_buffer,"Non-Authoritative");
            strcat((char*)client_buffer,"\n");
            strcat((char*)client_buffer,"Name: ");
            strcat((char*)client_buffer,(char*)answers[i].name);
            strcat((char*)client_buffer," has PTR record: ");
            strcat((char*)client_buffer,(char*)answers[i].rdata);
            strcat((char*) client_buffer,"\0");
            strcat((char*) client_buffer,"\n");
        }
        else if(ntohs(answers[i].resource->type) == 15) // MX record
        {
            // MX record has a preference value followed by the mail exchange domain name
            unsigned short preference = ntohs(*(unsigned short*)reader);
            reader += 2;

            unsigned char* mx_name = (unsigned char*)malloc(2000);
            mx_name=read_name(reader, buf, &stop);

            char preference_str[6];
            memset(preference_str,0,6);
            sprintf(preference_str, "%d", preference);

            answers[i].rdata = (unsigned char*)malloc(2 + strlen((char*)mx_name)+2); // allocate memory for preference, space, mx_name, and null terminator
            memset(answers[i].rdata,0,4+strlen((char*)mx_name));
            sprintf((char*)answers[i].rdata, "%s %s", preference_str, mx_name);
            free(mx_name);

            reader += (ntohs(answers[i].resource->data_len) - 2);

            add_cache(answers[i].name,&answers[i],1);

            if(i==0)
            {
                strcat((char*)client_buffer,"Non-Authoritative\n");
                strcat((char*)client_buffer,"Name: ");
                strcat((char*)client_buffer,(char*)answers[i].name);
                strcat((char*)client_buffer," has MX record: ");
                strcat((char*)client_buffer,(char*)answers[i].rdata);
                strcat((char*) client_buffer,"\n");

            }
            else
            {
                strcat((char*)client_buffer,(char*)answers[i].rdata);
                strcat((char*) client_buffer,"\n");
            }

        }
        else if(ntohs(answers[i].resource->type)==2)
        {
            answers[i].rdata = read_name(reader, buf, &stop);
            reader += stop;

            add_cache(answers[i].name, &answers[i], 1);

            if(i==0)
            {
                strcat((char*)client_buffer,"Non-Authoritative\n");
                strcat((char*)client_buffer,"Name: ");
                strcat((char*)client_buffer,(char*)answers[i].name);
                strcat((char*)client_buffer," has NS record:\n");
                strcat((char*)client_buffer,(char*)answers[i].rdata);
                strcat((char*) client_buffer,"\n");
            }
            else
            {
                strcat((char*)client_buffer,(char*)answers[i].rdata);
                strcat((char*) client_buffer,"\n");
            }
        }
        else
        {
            answers[i].rdata=(unsigned char*)malloc(1000);
            memset(answers[i].rdata,0,1000);
            answers[i].rdata=read_name(reader,buf,&stop);
            reader=reader+stop;
        }
    }

    size_t length = strlen((const char*)client_buffer);

    if (sendto(sockfd, client_buffer, length, 0, (struct sockaddr *)&client, client_len) < 0) 
    {
        log_message("Failed to send response to client!", logFile);
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
    for (int i = 0; i < n && buffer[i] != '\0'; ++i) 
    {
        if (!std::isalnum(buffer[i]) && buffer[i] != '.' && buffer[i] != '-') 
        {
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
    memset(name,0,256);

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
    memset(new_name,0,1000);
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

void reverse_dns_request(int sockfd, int google_sockfd, sockaddr_in client, socklen_t client_len,char* ip_address)
{
    std::cout<<"reverse"<<std::endl;
    log_message("Reverse request.", logFile);

    struct in_addr addr;
    unsigned char buf[BUFFER_SIZE],*name,*reader;
    memset(buf,0,sizeof(buf));

    if (inet_pton(AF_INET, ip_address, &addr) <= 0) 
    {
        strcpy((char*)buf,(char*)"Invalid IP address: ");
        strcat((char*)buf, ip_address);
        strcat((char*)buf,"\n");

        if (sendto(sockfd, buf, strlen((char*)buf), 0, (struct sockaddr *)&client, client_len) < 0) 
        {
            log_message("Failed to send response to client!", logFile);
            exit(EXIT_FAILURE);
        }
        return;
    }

    char reverse_ip[256];
    int a, b, c, d;

    sscanf((char*)ip_address, "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(reverse_ip, sizeof(reverse_ip), "%d.%d.%d.%d.in-addr.arpa", d, c, b, a);

    //cache verify
    for (auto& entry : cache) 
    {
        if (entry.reverse_ip && strcmp((char*)entry.reverse_ip, reverse_ip) == 0) 
        {
            entry.timer=86400;
            std::string response = "Reverse Lookup (cached): ";
            response += (char*)entry.resolved_name;
            response +="\n";
            log_message("From cache.", logFile);
            sendto(sockfd, response.c_str(), response.size(), 0, (struct sockaddr*)&client, client_len);
            return;
        }
    }

    char resolved_name[256];
    if(verify_reverse_file(reverse_ip,resolved_name))
    {
        struct RES_RECORD* reverse_record = (RES_RECORD*)malloc(sizeof(RES_RECORD));
        reverse_record->name = (unsigned char*)malloc(256);
        strcpy((char*)reverse_record->name, resolved_name);
        reverse_record->rdata = (unsigned char*)malloc(256);
        strcpy((char*)reverse_record->rdata,reverse_ip);
        reverse_record->resource = (struct R_DATA*)malloc(sizeof(struct R_DATA));
        reverse_record->resource->type=12;
        add_cache((unsigned char*)resolved_name,reverse_record,0);

        unsigned char response[BUFFER_SIZE];
        strcpy((char*)response,"Reverse Lookup: ");
        strcat((char*)response,resolved_name);
        strcat((char*)response,"\n");
        
        if (sendto(sockfd, response, strlen((char*)response), 0, (struct sockaddr *)&client, client_len) < 0) 
        {
            log_message("Failed to send response to client!", logFile);
            exit(EXIT_FAILURE);
        }
        return;
    }

    //forward
   forward_dns_request(sockfd,google_sockfd,client,client_len,(unsigned char*)reverse_ip,12);
}

bool verify_reverse_file(char* reverse_ip, char* resolved_name)
{
    std::ifstream file("ReverseFile");

    if (!file.is_open()) 
    {
        log_message("Error opening ReverseFile!", logFile);
        return false;
    }

    std::string line;
    while(std::getline(file,line))
    {
        std::istringstream iss(line);
        std::string ip,name,type;
        iss>>ip>>type>>name;
        if(ip==reverse_ip)
        {
            strcpy(resolved_name,name.c_str());
            return 1;
        }
    }
    file.close();
    return 0;
}

void handle_dns_request(int sockfd, int google_sockfd, sockaddr_in client, socklen_t client_len, unsigned char* buffer,int n)
{
    if (strncmp((char*)buffer, "12 ", 3) == 0) //-X
    {
        char ip_address[INET_ADDRSTRLEN];
        sscanf((char*)buffer + 3, "%s", ip_address);
        reverse_dns_request(sockfd,google_sockfd, client, client_len, ip_address);
    }
    else if (strncmp((char*)buffer, "15 ", 3) == 0) //-MX
    {
        unsigned char domain_name[BUFFER_SIZE];
        sscanf((char*)buffer + 3, "%s", domain_name);
        log_message("MX request.", logFile);

        if(verify_cache(sockfd,domain_name,n,client,client_len,15)==0)
        {
            if(verify_master_file(sockfd,client,client_len,domain_name,n, 15)==0)
            {   
                forward_dns_request(sockfd,google_sockfd,client,client_len,domain_name,15); //doar ipv4
            }
        }
        
    }
    else if (strncmp((char*)buffer, "28 ", 3) == 0) //-AAAA
    {
        unsigned char domain_name[BUFFER_SIZE];
        sscanf((char*)buffer + 3, "%s", domain_name);
        log_message("AAAA request.", logFile);

        if(verify_cache(sockfd,domain_name,n,client,client_len,28)==0)
        {
            if(verify_master_file(sockfd,client,client_len,domain_name,n, 28)==0)
            {
                forward_dns_request(sockfd,google_sockfd,client,client_len,domain_name,28); //doar ipv4
            }
        }
        
    }
    else if (strncmp((char*)buffer, "2 ", 2) == 0) //-NS
    {
        unsigned char domain_name[BUFFER_SIZE];
        sscanf((char*)buffer + 2, "%s", domain_name);
        log_message("NS request.", logFile);

        if(verify_cache(sockfd,domain_name,n,client,client_len,2)==0)
        {
            if(verify_master_file(sockfd,client,client_len,domain_name,n, 2)==0)
            {
                forward_dns_request(sockfd,google_sockfd,client,client_len,domain_name,2); //doar ipv4
            }
        }
        
    }
    else if(is_plain_text_domain(buffer, n)==0) 
    {
        dig_dns_request(sockfd,google_sockfd,n,buffer,client,client_len);
    }
    else
    {
        log_message("IPv4 request.", logFile);
        if(verify_cache(sockfd,buffer,n,client,client_len,1)==0)
        {
            if(verify_master_file(sockfd,client,client_len,buffer,n,1)==0)
            {
                forward_dns_request(sockfd,google_sockfd,client,client_len,buffer,1); //doar ipv4
            }
        }
    }
}

void add_edns_section(unsigned char *buf, int *offset) 
{
    struct EDNS *edns = (struct EDNS *)&buf[*offset];
    edns->name = 0;
    edns->type = htons(41);
    edns->udp_payload_size = htons(EDNS_PAYLOAD_SIZE);
    edns->extended_rcode = 0;
    edns->edns_version = 0;
    edns->z = 0;
    edns->data_length = htons(CLIENT_COOKIE_LEN + 4); 

    struct COOKIE_OPTION *cookie_option = (struct COOKIE_OPTION *)edns->data;
    cookie_option->option_code = htons(COOKIE_OPTION_CODE);
    cookie_option->option_length = htons(CLIENT_COOKIE_LEN);
    
    // generate random code
    for (int i = 0; i < CLIENT_COOKIE_LEN; i++) 
    {
        cookie_option->client_cookie[i] = rand() % 256;
    }

    *offset += sizeof(struct EDNS) + CLIENT_COOKIE_LEN + 4;
}

void init_log_file(std::ofstream& logFile) 
{
    logFile.open("LogFile", std::ios::out | std::ios::app);
    if (!logFile.is_open()) 
    {
        log_message("Failed to open logFile!", logFile);
        exit(EXIT_FAILURE);
    }
}

void log_message(const std::string& message, std::ofstream& logFile) 
{
    if (logFile.is_open()) 
    {
        std::time_t now = std::time(nullptr);
        logFile << "[" << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
    }
}
