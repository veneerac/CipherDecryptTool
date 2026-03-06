package org.veneera.password_decrypter;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;

public class DecryptPasswords {

    public static void main(String[] args) {
        try {
            // --------------------------
            // Load config
            // --------------------------
            Properties config = new Properties();
            File configFile = new File("config.properties");
            if (!configFile.exists()) {
                throw new RuntimeException("config.properties not found in: " + configFile.getAbsolutePath());
            }
            try (FileInputStream fis = new FileInputStream(configFile)) {
                config.load(fis);
            }

            String keystoreFile    = requireProperty(config, "keystore.file");
            String keystorePassword = requireProperty(config, "keystore.password");
            String keyAlias        = requireProperty(config, "key.alias");
            String keyPassword     = config.getProperty("key.password", ""); // optional
            String inputFile       = requireProperty(config, "input.file");
            String outputFile      = requireProperty(config, "output.file");

            // Validate files exist before proceeding
            validateFileExists(keystoreFile, "Keystore");
            validateFileExists(inputFile, "Input");

            // --------------------------
            // Load JKS keystore
            // --------------------------
            KeyStore ks = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                ks.load(fis, keystorePassword.toCharArray());
            }

            if (!ks.isKeyEntry(keyAlias)) {
                throw new RuntimeException("Alias '" + keyAlias + "' not found in keystore");
            }

            Key key = ks.getKey(keyAlias, keyPassword.isEmpty() ? null : keyPassword.toCharArray());
            if (!(key instanceof PrivateKey)) {
                throw new RuntimeException("Key is not a private key");
            }
            PrivateKey privateKey = (PrivateKey) key;

            // --------------------------
            // Read input file and decrypt
            // --------------------------
            try (BufferedReader reader = Files.newBufferedReader(Paths.get(inputFile));
                 BufferedWriter writer = Files.newBufferedWriter(Paths.get(outputFile))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    // Skip blank lines
                    if (line.isBlank()) {
                        writer.write("\n");
                        continue;
                    }

                    if (!line.contains("=")) {
                        writer.write(line + "  # Invalid line, skipped\n");
                        continue;
                    }

                    String[] parts = line.split("=", 2);
                    String keyName  = parts[0].trim();
                    String encValue = parts[1].trim();

                    if (encValue.isEmpty()) {
                        writer.write(keyName + "=\n");
                        continue;
                    }

                    try {
                        byte[] cipherBytes = Base64.getDecoder().decode(encValue);
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.DECRYPT_MODE, privateKey);
                        byte[] decrypted = cipher.doFinal(cipherBytes);
                        String decryptedValue = new String(decrypted);

                        writer.write(keyName + "=" + decryptedValue + "\n");
                        System.out.println(keyName + "=" + decryptedValue);

                    } catch (Exception e) {
                        writer.write(keyName + "=# ERROR: " + e.getMessage() + "\n");
                        System.err.println("ERROR decrypting '" + keyName + "': " + e.getMessage());
                    }
                }
            }

            System.out.println("\nDecryption completed. See " + outputFile);

        } catch (RuntimeException e) {
            System.err.println("Configuration error: " + e.getMessage());
            System.exit(1);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Fetches a required property, throwing a clear error if it's missing or blank.
     */
    private static String requireProperty(Properties config, String key) {
        String value = config.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new RuntimeException("Missing required property '" + key + "' in config.properties");
        }
        return value.trim();
    }

    /**
     * Validates that a file path exists and is readable.
     */
    private static void validateFileExists(String path, String label) {
        File f = new File(path);
        if (!f.exists()) {
            throw new RuntimeException(label + " file not found: " + f.getAbsolutePath());
        }
        if (!f.canRead()) {
            throw new RuntimeException(label + " file is not readable: " + f.getAbsolutePath());
        }
    }
}