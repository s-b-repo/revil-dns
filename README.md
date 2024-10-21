# revil-dns
a sliver c2 payload for connecting to the c2 using dns and obfuscation written in c 


important details:

# DNS-based C2 Over SSL

This project implements a covert Command & Control (C2) client that communicates over DNS (port 53) using SSL encryption. The DNS traffic is obfuscated to resemble legitimate DNS queries while actually relaying commands and responses between the infected host and the C2 server. This approach helps evade detection by traditional firewalls and network intrusion detection systems (IDS).

## Features

- **DNS disguise:** The communication between the client and the C2 server is disguised as DNS queries over port 53.
- **SSL encryption:** Data transfer between the client and server is encrypted using SSL, adding an extra layer of security.
- **Remote command execution:** The C2 client can execute remote commands on the infected machine, such as:
  - Change directory (`cd`)
  - Get current directory (`pwd`)
  - List installed applications
  - Keylogging for a specified duration
  - Execute system commands via `cmd`
- **Randomized sleep:** Polymorphic behavior is achieved through random sleep intervals to avoid detection by behavioral analysis tools.

## Requirements

- Windows OS
- Visual Studio or other compatible C/C++ compiler
- OpenSSL for SSL/TLS support

## Setup Instructions

1. **Install OpenSSL:**
   - Download and install OpenSSL from [here](https://www.openssl.org/).
   - Ensure the OpenSSL library is linked properly with your project.

2. **Compile the code:**
   - Ensure you have a C compiler installed (like GCC or MSVC).
   - Link the necessary libraries (e.g., `ws2_32.lib`, `libssl.lib`, `libcrypto.lib`).
   - Compile the code by running the following commands (adapt to your environment):
     ```
     gcc -o dns_c2_client dns_c2_client.c -lssl -lcrypto -lws2_32
     ```

3. **Configure the C2 server:**
   - Replace the `C2_SERVER_IP` in the code with the IP address of your actual C2 server.

4. **Run the executable:**

./dns_c2_client.exe

## How It Works

1. The client initiates communication over TCP port 53, disguising traffic as DNS queries.
2. The C2 server responds with commands, which are executed on the infected machine.
3. Results from the executed commands are sent back to the C2 server over the same disguised channel.
4. All communication is encrypted using SSL to ensure data confidentiality.

### Commands Supported

- `CD <path>`: Changes the working directory to the specified path.
- `PWD`: Returns the current working directory.
- `LIST_APPS`: Lists all installed applications on the system.
- `KEYLOG <duration>`: Captures keystrokes for the specified duration (in seconds).
- `CMD <command>`: Executes a system command and sends the output to the C2 server.

## Disclaimer

**This project is for educational and research purposes only.**

This project is for educational purposes only. Do not use this code for any illegal activity, unauthorized network penetration, or without proper permission. Always ensure you are compliant with local laws and have the necessary authorization before executing any penetration tests or obfuscated traffic generation in a network environment.
