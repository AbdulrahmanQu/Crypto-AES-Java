# 🔐 Crypto-AES: A Secure Client-Server Program

A simple Java client-server application demonstrating secure communication using **AES-256** for message encryption and **RSA** for the secure exchange of the AES key.

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
* `screenshots/`: A directory containing screenshots of the GUI and example outputs.

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

1.  **Ensure Java is installed** and your `PATH` is configured correctly. You can check with `java --version`.

2.  **Compile all Java files:**
    Open a terminal in the project directory and run:
    ```sh
    javac *.java
    ```

3.  **Run the Server:**
    The server must be started first to listen for connections.
    ```sh
    java Server
    ```

4.  **Run the Client:**
    In a new terminal window, run:
    ```sh
    java Client
    ```

### Usage
* **Client GUI:** Type a message into the text field and click **"Encrypt & Send"**. The client will display the AES ciphertext and the RSA-encrypted AES key.
* **Server GUI:** Once the message is received, click **"Decrypt"**. The original plaintext message will appear.

---

## Example Output

Here is a typical sequence of events shown in the terminal:

**Server Terminal:**

[2025/10/03]abdel@Host:~/Crypto-AES$ java Server
Server: RSA keypair generated (2048 bits).
Server: Listening on port 5555...
Server: Received RSA-encrypted AES key (256 bytes).
Server: Decrypted AES key successfully.
Server: Received ciphertext (IV + data).


**Client Terminal:**
[2025/10/03]abdel@Host:~/Crypto-AES$ java Client
Client: Connected to server 127.0.0.1:5555
Client: Received server public key.
Client: Generated AES-256 key.
Client: Encrypted AES key with server RSA public key and sent to server.


**GUI Example:**
* **Plaintext typed in Client:** `Hello Crypto`
* **Ciphertext shown in Client (hex):** `f8a3b4c90d2f1e...`
* **Decrypted message shown on Server:** `Hello Crypto`

---

## Security Considerations

* **AES-256** is used for its speed and strength in encrypting the bulk data (the message).
* **RSA-2048** provides a secure channel for exchanging the AES key. Since the AES key is encrypted with the server's public key, only the server can decrypt it with its private key, preventing eavesdroppers from intercepting the session key.
* **For Production Systems:** This project is for educational purposes. A real-world application should use an authenticated encryption mode like **AES-GCM** to protect against tampering, implement proper key validation, use cryptographically secure random number generators for keys and IVs, and securely store the server's private key.

