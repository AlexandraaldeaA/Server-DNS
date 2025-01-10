#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <csignal>

#define SERVER_PORT 1053
#define SERVER_IP "172.20.10.2"
#define BUFFER_SIZE 512

void handle_sigint(int);

int sock=-1;

int main(int argc, char** argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, nullptr);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        std::cout << "Failed to create socket." << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) 
    {
        std::cout << "Invalid server IP address." << std::endl;
        close(sock);
        return 1;
    }

    char str[BUFFER_SIZE] = "";
    if (argc == 1)
    {
        std::cout<< "Use: mydns <domain_name> : IPv4"<<std::endl;
        std::cout<< "Use: mydns -AAAA <domain_name> : IPv6"<<std::endl;
        std::cout<< "Use: mydns -MX <domain_name> : Mail Exchange"<<std::endl;
        std::cout<< "Use: mydns -NS <domain_name> : Name Server"<<std::endl;
        std::cout<< "Use: mydns -X <adresa_IPv4> : Reverse"<<std::endl;
        return 1;
    } 
    if (argc > 3)
    {
        std::cout << "Error: You cannot enter more than 2 arguments!" << std::endl;
        return 1;
    } 
    if (argc == 3)
    {
        if (strcmp(argv[1], "-X") == 0)
        {
            strcpy(str, "12 ");
        }  
        else if (strcmp(argv[1], "-MX") == 0)
        {
            strcpy(str, "15 ");
        }
        else if (strcmp(argv[1], "-AAAA") == 0)
        {
            strcpy(str, "28 ");
        }
        else if (strcmp(argv[1], "-NS") == 0)
        {
            strcpy(str, "2 ");
        }
        strcat(str, argv[2]);
    }
    else if (argc == 2)
    {
        strcat(str, argv[1]);
    }

    std::string message(str);
    ssize_t sent_bytes = sendto(sock, message.c_str(), message.size(), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent_bytes < 0) 
    {
        std::cout << "Failed to send message to server." << std::endl;
        close(sock);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t received_bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&from_addr, &from_len);
    if (received_bytes < 0) 
    {
        std::cout << "Error receiving data from server." << std::endl;
    } 
    else 
    {
        buffer[received_bytes] = '\0';
        std::cout << buffer;
    }

    close(sock);
    return 0;
}

void handle_sigint(int sig)
{
    std::cout << "\nGraceful termination triggered. Cleaning up resources..." << std::endl;
    if (sock != -1) 
    {
        close(sock); // Închidem socket-ul dacă este deschis
        std::cout << "Socket closed." << std::endl;
    }
    exit(0);
}