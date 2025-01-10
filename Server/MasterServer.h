#ifndef MASTERSERVER_H
#define MASTERSERVER_H

#include <sys/socket.h>	
#include <stdio.h>	
#include <string.h>	
#include <stdlib.h>	
#include <arpa/inet.h>	
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <memory>
#include <mutex>

#define BUFFER_SIZE 512
#define GOOGLE_DNS "8.8.8.8"
#define GOOGLE_DNS_PORT 53
#define DNS_PORT 12345
#define EDNS_PAYLOAD_SIZE 1232
#define COOKIE_OPTION_CODE 10
#define CLIENT_COOKIE_LEN 8
#define LIMIT_CACHE 2
#define MAX_EVENTS 12
#define TIMEOUT_MS 1000 

std::ofstream logFile;
std::mutex socket_mutex; // mutex pentru protejarea accesului la socket
std::mutex logMutex;
std::mutex cacheMutex;
std::mutex reverse;
std::mutex masterfile;

struct DNS_HEADER
{
	uint16_t id; //id to match up

	unsigned char rd :1; //recursion desidered
	unsigned char tc :1; //truncated or not
	unsigned char aa :1; //bit-specifies that the responding name server is an authority for the domain name in question section.
	unsigned char opcode :4; //4 bit field-what kind of query(0-query, 1-inverse query,2 server status request)
	unsigned char qr :1; //bit field-just a bit to specify if it is query(0) or response(1)

	unsigned char rcode :4; //for responses(errors, format errors,name errrors, etc)
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; //must be 0 in all queries and responses, for future use
	unsigned char ra :1; // recursion available

	uint16_t q_count; // number of question entries
	uint16_t ans_count; // number of answer entries
	uint16_t auth_count; // number of authority entries
	uint16_t add_count; // number of resource entries
};

struct QUESTION
{
	uint16_t qtype; //type of query
	uint16_t qclass; //class of query
};


struct R_DATA
{
	uint16_t type;
	uint16_t _class;
	int32_t ttl;
	uint16_t data_len;
} __attribute__((packed));


struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

struct QUERY
{
    unsigned char* name;
    struct QUESTION* question;
};

struct EDNS {
    uint8_t name; // 0 (root domain)
    uint16_t type; // 41 (OPT)
    uint16_t udp_payload_size; // 1232
    uint8_t extended_rcode; // 0
    uint8_t edns_version; // 0
    uint16_t z; // 0
    uint16_t data_length; // Length of the data
    unsigned char data[]; // EDNS Data
} __attribute__((packed));

struct COOKIE_OPTION {
    uint16_t option_code; // 10
    uint16_t option_length; 
    unsigned char client_cookie[CLIENT_COOKIE_LEN]; // Client COOKIE
    unsigned char server_cookie[]; // Server COOKIE (if exists)
} __attribute__((packed));

struct CACHE {
	unsigned char* domain_name;
	unsigned char* ip_address;
	uint16_t type;
	unsigned char* reverse_ip;
    unsigned char* resolved_name;
	int timer;
};

std::vector<CACHE> cache;

#endif
