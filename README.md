# 🔐 Crypto-AES: A Secure Client-Server Program

A simple Java client-server application demonstrating secure communication using **AES-2-56** for message encryption and **RSA** for the secure exchange of the AES key.

---

## Overview

This project implements a GUI-based client-server system in Java to showcase a hybrid encryption model. The primary goal is to demonstrate how symmetric (AES) and asymmetric (RSA) cryptography can work together to establish a secure communication channel.

**Key Objectives:**
* Demonstrate the synergy between symmetric and asymmetric encryption.
* Show the full cryptographic cycle: plaintext → ciphertext → decrypted plaintext.
* Provide an easy-to-use graphical interface for verification.

---

## Prerequisites

To compile and run this project, you'll need:
* **Java Development Kit (JDK)** version 11 or higher.
* A terminal or an IDE (like VS Code, IntelliJ, or Eclipse).
* Basic knowledge of Java and network sockets.

---

## Files in this Repository

* `Client.java`: The client program with a Java Swing GUI. It generates an AES key, encrypts the user's message, encrypts the AES key with the server's public RSA key, and sends both to the server.
* `Server.java`: The server program with a Java Swing GUI. It generates an RSA key pair, waits for a client, receives the encrypted data, decrypts the AES key using its private RSA key, and then decrypts the message.
* `RSAKeyPairGenerator.java`: An optional helper utility to generate an RSA key pair.
* `README.md`: This file.
* `images/`: A directory containing screenshots of the GUI and example outputs.

---

## Design and Flow

The communication protocol follows a standard hybrid encryption flow:

1.  **RSA Key Pair Generation (Server-Side)**
    The server starts by generating a **2048-bit RSA key pair** (a public key and a private key). It then listens for a client connection and sends its **public key** to the client.

2.  **AES Key Generation (Client-Side)**
    Upon receiving the server's public key, the client generates its own secret **256-bit AES key**. This key will be used for encrypting the actual message.

3.  **Secure AES Key Exchange**
    The client encrypts its newly generated **AES key** using the server's **RSA public key**. This ensures that only the server, which holds the corresponding private key, can decrypt and view the AES key. The client then sends this RSA-encrypted AES key to the server.

4.  **Message Encryption with AES**
    The client uses the symmetric **AES key** (typically in CBC or GCM mode) to encrypt the plaintext message typed by the user. The resulting ciphertext (and the Initialization Vector, if applicable) is sent to the server.

5.  **Decryption (Server-Side)**
    The server receives two pieces of data: the RSA-encrypted AES key and the AES-encrypted message.
    * First, it uses its **RSA private key** to decrypt the AES key.
    * Second, it uses the now-decrypted **AES key** to decrypt the message ciphertext, successfully retrieving the original plaintext.

---

## How to Compile and Run

### 1. Compile the Java Source Files
This command compiles all `.java` files from the `src/cryptoaes` directory. The `-d bin` flag places the resulting `.class` files into the `bin` directory.
```sh
javac -d bin src/cryptoaes/*.java

2. Run the Server
Execute this command to start the server. The -cp bin flag tells Java to look for the compiled classes in the bin directory.

Bash

java -cp bin cryptoaes.Server
3. Run the Client (in a separate terminal)
Finally, run this command in a new terminal to start the client application.

Bash

java -cp bin cryptoaes.Client
## Step-by-Step Demonstration

The following images illustrate the complete process, from running the programs to the final decryption.

### 1. Running the Client & Server (Key Exchange)
After compiling, the server and client are run in separate terminals. The client immediately connects to the server, and the secure key exchange takes place. The terminal logs show the client receiving the server's RSA public key and sending back the RSA-encrypted AES key.

![Running the Client and Server](images/Running%20the%20Client%20and%20Server.jpg)

### 2. Encryption
The user types the plaintext message "SEC6651" into the client GUI and clicks "Encrypt & Send". The client uses the AES key to encrypt the message and sends the resulting ciphertext to the server. The client GUI now displays the Base64 ciphertext, and the server GUI shows it has been received.

![Encryption](images/Encryption.jpg)

### 3. Decryption
The user clicks the "Decrypt" button on the server GUI. The server uses the AES key it received to decrypt the ciphertext, successfully revealing the original plaintext message "SEC6651". This completes the secure communication cycle.

![Decryption](images/Decryption.jpg)
