package cryptoaes;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    private static final int PORT = 5555;

    // Runtime state for single client
    private PrivateKey rsaPrivate;
    private byte[] aesKeyBytes; // 32 bytes
    private byte[] lastIv;
    private byte[] lastCiphertext;

    // GUI components
    private JFrame frame;
    private JTextArea logArea;
    private JTextField aesKeyField;
    private JTextField ciphertextField;
    private JTextArea decryptedArea;
    private JButton decryptButton;

    public static void main(String[] args) throws Exception {
        Server s = new Server();
        s.startGUI();
        s.startServer(); // start listening concurrently
    }

    private void startGUI() {
        frame = new JFrame("Crypto-AES Server");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(700, 500);

        JPanel top = new JPanel(new BorderLayout());
        logArea = new JTextArea(6, 60);
        logArea.setEditable(false);
        top.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel mid = new JPanel(new GridLayout(3,1));
        aesKeyField = new JTextField();
        aesKeyField.setEditable(false);
        mid.add(labeledPanel("AES Key (Base64) - received after key-exchange:", aesKeyField));

        ciphertextField = new JTextField();
        ciphertextField.setEditable(false);
        mid.add(labeledPanel("Last received Ciphertext (Base64):", ciphertextField));

        decryptedArea = new JTextArea(6,60);
        decryptedArea.setEditable(false);
        mid.add(labeledPanel("Decrypted Plaintext (press Decrypt):", new JScrollPane(decryptedArea)));

        decryptButton = new JButton("Decrypt");
        decryptButton.setEnabled(false);
        decryptButton.addActionListener((ActionEvent e) -> onDecryptPressed());

        frame.getContentPane().add(top, BorderLayout.NORTH);
        frame.getContentPane().add(mid, BorderLayout.CENTER);
        frame.getContentPane().add(decryptButton, BorderLayout.SOUTH);

        frame.setVisible(true);
        appendLog("Server GUI ready.");
    }

    private JPanel labeledPanel(String label, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(label), BorderLayout.NORTH);
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void appendLog(String s) {
        SwingUtilities.invokeLater(() -> logArea.append(s + "\n"));
    }

    private void startServer() {
        Thread t = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(PORT)) {
                appendLog("Server listening on port " + PORT);
                KeyPair kp = CryptoUtils.generateRSAKeyPair(2048);
                rsaPrivate = kp.getPrivate();
                // Wait for a single client for demo; can loop for multiple clients
                while (true) {
                    Socket sock = ss.accept();
                    appendLog("Client connected: " + sock.getRemoteSocketAddress());
                    handleClient(sock, kp);
                }
            } catch (Exception ex) {
                appendLog("Server error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void handleClient(Socket sock, KeyPair kp) {
        Thread t = new Thread(() -> {
            try (DataInputStream dis = new DataInputStream(sock.getInputStream());
                 DataOutputStream dos = new DataOutputStream(sock.getOutputStream())) {

                // 1) Send server RSA public key (X.509 encoded)
                byte[] pubBytes = kp.getPublic().getEncoded();
                dos.writeInt(pubBytes.length);
                dos.write(pubBytes);
                dos.flush();
                appendLog("Sent RSA public key (" + pubBytes.length + " bytes) to client.");

                // 2) Receive RSA-encrypted AES key length + bytes
                int encKeyLen = dis.readInt();
                byte[] encKey = new byte[encKeyLen];
                dis.readFully(encKey);
                appendLog("Received encrypted AES key (" + encKeyLen + " bytes).");

                // Decrypt AES key
                byte[] aesBytes = CryptoUtils.rsaDecrypt(encKey, rsaPrivate);
                this.aesKeyBytes = aesBytes;
                appendLog("AES key decrypted (" + aesBytes.length + " bytes).");
                SwingUtilities.invokeLater(() -> aesKeyField.setText(CryptoUtils.toBase64(aesBytes)));

                // 3) Now handle incoming messages: client will send messages as: ivLen, ivBytes, ctLen, ctBytes
                while (true) {
                    int ivLen;
                    try {
                        ivLen = dis.readInt();
                    } catch (EOFException eof) {
                        appendLog("Client disconnected.");
                        break;
                    }
                    byte[] iv = new byte[ivLen];
                    dis.readFully(iv);

                    int ctLen = dis.readInt();
                    byte[] ct = new byte[ctLen];
                    dis.readFully(ct);

                    // store last ciphertext & iv, enable decrypt button
                    this.lastIv = iv;
                    this.lastCiphertext = ct;
                    String ctB64 = CryptoUtils.toBase64(ct);
                    SwingUtilities.invokeLater(() -> {
                        ciphertextField.setText(ctB64);
                        decryptButton.setEnabled(true);
                    });
                    appendLog("Received ciphertext (len=" + ctLen + "). Ready to decrypt.");
                }

            } catch (Exception ex) {
                appendLog("Client handler error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void onDecryptPressed() {
        if (aesKeyBytes == null || lastCiphertext == null || lastIv == null) {
            JOptionPane.showMessageDialog(frame, "No AES key or ciphertext available.");
            return;
        }
        try {
            SecretKeySpec key = CryptoUtils.makeAESKeyFromBytes(aesKeyBytes);
            byte[] pt = CryptoUtils.aesDecrypt(lastCiphertext, key, lastIv);
            String plain = new String(pt, "UTF-8");
            decryptedArea.setText(plain);
            appendLog("Decryption successful. Plaintext displayed.");
        } catch (Exception ex) {
            appendLog("Decryption error: " + ex.getMessage());
            ex.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Decryption failed: " + ex.getMessage());
        }
    }
}

