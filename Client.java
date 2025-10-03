package cryptoaes;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private static final String SERVER_HOST = "localhost"; // change to server IP if needed
    private static final int SERVER_PORT = 5555;

    // Runtime state
    private PublicKey serverPub;
    private byte[] aesKeyBytes;
    private Socket socket;
    private DataOutputStream dos;
    private DataInputStream dis;

    // GUI
    private JFrame frame;
    private JTextArea plaintextArea;
    private JTextArea ciphertextArea;
    private JTextField aesKeyField;
    private JButton encryptButton;

    public static void main(String[] args) throws Exception {
        Client c = new Client();
        c.startGUI();
        c.connectToServer();
    }

    private void startGUI() {
        frame = new JFrame("Crypto-AES Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(700, 500);

        JPanel top = new JPanel(new BorderLayout());
        plaintextArea = new JTextArea(6, 60);
        top.add(labeledPanel("Plaintext (type message here):", new JScrollPane(plaintextArea)), BorderLayout.CENTER);

        ciphertextArea = new JTextArea(6, 60);
        ciphertextArea.setEditable(false);

        aesKeyField = new JTextField();
        aesKeyField.setEditable(false);

        encryptButton = new JButton("Encrypt & Send");
        encryptButton.setEnabled(false);
        encryptButton.addActionListener((ActionEvent e) -> onEncryptAndSend());

        JPanel mid = new JPanel(new GridLayout(2,1));
        mid.add(labeledPanel("Ciphertext (Base64):", new JScrollPane(ciphertextArea)));
        mid.add(labeledPanel("AES Key (Base64):", aesKeyField));

        frame.getContentPane().add(top, BorderLayout.NORTH);
        frame.getContentPane().add(mid, BorderLayout.CENTER);
        frame.getContentPane().add(encryptButton, BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private JPanel labeledPanel(String label, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(label), BorderLayout.NORTH);
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void connectToServer() {
        Thread t = new Thread(() -> {
            try {
                socket = new Socket(SERVER_HOST, SERVER_PORT);
                dos = new DataOutputStream(socket.getOutputStream());
                dis = new DataInputStream(socket.getInputStream());
                log("Connected to server " + socket.getRemoteSocketAddress());

                // 1) Receive server RSA public key
                int pubLen = dis.readInt();
                byte[] pubBytes = new byte[pubLen];
                dis.readFully(pubBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
                serverPub = kf.generatePublic(spec);
                log("Received server RSA public key (" + pubLen + " bytes).");

                // 2) Generate AES-256 key (32 bytes), send it encrypted with server RSA
                aesKeyBytes = CryptoUtils.generateAESKeyBytes(32); // 32 bytes = 256 bits
                byte[] encKey = CryptoUtils.rsaEncrypt(aesKeyBytes, serverPub);
                dos.writeInt(encKey.length);
                dos.write(encKey);
                dos.flush();
                log("Sent RSA-encrypted AES key (" + encKey.length + " bytes).");
                SwingUtilities.invokeLater(() -> {
                    aesKeyField.setText(CryptoUtils.toBase64(aesKeyBytes));
                    encryptButton.setEnabled(true);
                });

                // We don't expect more incoming data in client other than server disconnect notifications,
                // so we can leave this thread running to detect closure.
                while (!socket.isClosed()) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) { }
                }

            } catch (Exception ex) {
                log("Connection error: " + ex.getMessage());
                ex.printStackTrace();
                JOptionPane.showMessageDialog(frame, "Connection error: " + ex.getMessage());
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void onEncryptAndSend() {
        try {
            String plain = plaintextArea.getText();
            if (plain == null || plain.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please enter plaintext.");
                return;
            }
            SecretKeySpec key = CryptoUtils.makeAESKeyFromBytes(aesKeyBytes);
            CryptoUtils.CipherResult res = CryptoUtils.aesEncrypt(plain.getBytes("UTF-8"), key);

            // Update GUI
            String ctB64 = CryptoUtils.toBase64(res.ciphertext);
            ciphertextArea.setText(ctB64);

            // Send to server: ivLen + ivBytes + ctLen + ctBytes
            dos.writeInt(res.iv.length);
            dos.write(res.iv);
            dos.writeInt(res.ciphertext.length);
            dos.write(res.ciphertext);
            dos.flush();
            log("Encrypted and sent message (iv len=" + res.iv.length + ", ct len=" + res.ciphertext.length + ").");

        } catch (Exception ex) {
            log("Encrypt/send error: " + ex.getMessage());
            ex.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
        }
    }

    private void log(String s) {
        System.out.println("[Client] " + s);
    }
}

