# revil-dns
a sliver c2 payload for connecting to the c2 using dns and obfuscation written in c 


# Encrypted TCP Communication with DNS-like Obfuscation

This project demonstrates a technique to obfuscate TCP traffic by embedding HTTP requests into DNS-like queries and encrypting the communication using SSL/TLS. The project is intended for educational and research purposes, and only to be used in ethical penetration testing or network analysis environments.

**Note**: Ensure you have proper authorization before running this code in any environment. Unauthorized use of this technique could violate local laws.

## Features

- Mimics DNS queries and embeds HTTP requests within the DNS payload.
- Random data is added for obfuscation to evade basic pattern matching.
- Uses OpenSSL to encrypt TCP traffic between the client and the C2 server.
- Communicates over port 53 (commonly used for DNS traffic), disguising the true intent of the communication.

## Requirements

- **Windows**: The code uses Winsock2 for network communication, which is specific to Windows.
- **OpenSSL**: The OpenSSL library is required to provide SSL/TLS encryption for the TCP connection.
- **C2 Server**: The IP address of the C2 server must be provided. For testing purposes, you can set up a server to simulate the communication.

## Installation

1. **Install OpenSSL**:
   - Download and install OpenSSL from the [OpenSSL website](https://www.openssl.org/source/).
   - Ensure OpenSSL libraries and headers are properly configured in your system's include path.

2. **Clone this repository**:

   
   git clone https://github.com/s-b-repo/revil-dns.git
   cd revil-dns

    Install Dependencies:
        For Windows, install any dependencies required for Winsock and OpenSSL development.
        Ensure your compiler can link against the ws2_32.lib (for Winsock) and OpenSSL libraries.

Building
Using GCC (MinGW)

If you are using GCC with MinGW on Windows:

    Open a terminal in the project directory.
    Compile the program using:

    bash

    gcc -o rens.exe main.c -lws2_32 -lssl -lcrypto

Replace main.c with the actual name of the file containing your code.
Using Visual Studio

    Open the project in Visual Studio.
    Add the necessary include paths for Winsock and OpenSSL in the project settings.
    Build the project using Ctrl+Shift+B.

Usage

    Set the C2 Server IP:
        Open main.c and replace the placeholder C2_SERVER_IP with the actual IP address of the C2 server or a testing environment.

    Run the Program:
        Once compiled, run the executable:


        ./rens.exe

    Output:
        The program will:
            Initialize Winsock and OpenSSL.
            Connect to the C2 server over port 53 using encrypted TCP traffic.
            Send a DNS-like query with embedded HTTP requests.
            Receive a disguised response from the C2 server.

Disclaimer

This project is for educational purposes only. Do not use this code for any illegal activity, unauthorized network penetration, or without proper permission. Always ensure you are compliant with local laws and have the necessary authorization before executing any penetration tests or obfuscated traffic generation in a network environment.
