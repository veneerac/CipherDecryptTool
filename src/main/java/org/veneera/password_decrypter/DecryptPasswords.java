package org.veneera.password_decrypter;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;

public class DecryptPasswords {

    private static final String[] PADDING_SCHEMES = {
            "RSA/ECB/PKCS1Padding",
            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    };

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

            String keystoreFile     = requireProperty(config, "keystore.file");
            String keystorePassword = requireProperty(config, "keystore.password");
            String keyAlias         = requireProperty(config, "key.alias");
            String keyPassword      = config.getProperty("key.password", ""); // optional
            String inputFile        = requireProperty(config, "input.file");
            String outputFile       = requireProperty(config, "output.file");

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

            // Print key diagnostics to help debug wrong-key issues
            if (privateKey instanceof RSAPrivateKey) {
                RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
                int keyBits = rsaKey.getModulus().bitLength();
                int maxBytes = keyBits / 8 - 11; // PKCS1 overhead
                System.out.println("RSA key size : " + keyBits + " bits");
                System.out.println("Max cipher bytes (PKCS1): " + maxBytes);
                System.out.println("--------------------------------------------------");
            }

            // --------------------------
            // Read input file and decrypt
            // --------------------------
            int successCount = 0;
            int errorCount   = 0;

            try (BufferedReader reader = Files.newBufferedReader(Paths.get(inputFile));
                 BufferedWriter writer = Files.newBufferedWriter(Paths.get(outputFile))) {

                String line;
                while ((line = reader.readLine()) != null) {

                    // Preserve blank lines
                    if (line.isBlank()) {
                        writer.write("\n");
                        continue;
                    }

                    if (!line.contains("=")) {
                        writer.write(line + "  # Invalid line, skipped\n");
                        continue;
                    }

                    String[] parts    = line.split("=", 2);
                    String keyName    = parts[0].trim();
                    String encValue   = parts[1].trim();

                    if (encValue.isEmpty()) {
                        writer.write(keyName + "=\n");
                        continue;
                    }

                    // Strip WSO2-style {cipher} prefix if present
                    if (encValue.startsWith("{cipher}")) {
                        encValue = encValue.substring("{cipher}".length()).trim();
                    }

                    // Decode Base64 — catch bad encoding early with a clear message
                    byte[] cipherBytes;
                    try {
                        cipherBytes = Base64.getDecoder().decode(encValue);
                    } catch (IllegalArgumentException e) {
                        String msg = "Bad Base64 encoding — " + e.getMessage();
                        writer.write(keyName + "=# ERROR: " + msg + "\n");
                        System.err.println("ERROR (base64) '" + keyName + "': " + msg);
                        errorCount++;
                        continue;
                    }

                    // Warn if cipher bytes exceed what this key can handle
                    if (privateKey instanceof RSAPrivateKey) {
                        int keyBytes = ((RSAPrivateKey) privateKey).getModulus().bitLength() / 8;
                        if (cipherBytes.length > keyBytes) {
                            System.err.println("WARN  '" + keyName + "': cipher length " + cipherBytes.length
                                    + " bytes > key modulus " + keyBytes
                                    + " bytes — likely encrypted with a different key");
                        }
                    }

                    // Try each padding scheme in order
                    String decryptedValue = null;
                    String successScheme  = null;
                    StringBuilder schemeErrors = new StringBuilder();

                    for (String scheme : PADDING_SCHEMES) {
                        try {
                            Cipher cipher = Cipher.getInstance(scheme);
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);
                            byte[] decrypted = cipher.doFinal(cipherBytes);
                            decryptedValue = new String(decrypted).trim();
                            successScheme  = scheme;
                            break;
                        } catch (Exception e) {
                            schemeErrors.append("\n    [").append(scheme).append("] ")
                                    .append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
                        }
                    }

                    if (decryptedValue != null) {
                        writer.write(keyName + "=" + decryptedValue + "\n");
                        System.out.println("[OK:" + successScheme + "] " + keyName + "=" + decryptedValue);
                        successCount++;
                    } else {
                        String msg = "All padding schemes failed:" + schemeErrors;
                        writer.write(keyName + "=# ERROR: all paddings failed\n");
                        System.err.println("ERROR '" + keyName + "': " + msg);
                        errorCount++;
                    }
                }
            }

            System.out.println("--------------------------------------------------");
            System.out.printf("Decryption complete — %d succeeded, %d failed.%n", successCount, errorCount);
            System.out.println("Output written to: " + outputFile);

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