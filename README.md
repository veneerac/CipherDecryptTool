# 🔐 Cipher Decrypt — RSA Password Decryption Utility

A lightweight Java command-line tool that decrypts RSA-encrypted, Base64-encoded passwords stored in a `.properties` file using a private key from a JKS keystore.

---

## 📌 Features

- Decrypts RSA-encrypted values from a key=value input file
- Loads private key securely from a JKS keystore
- Writes decrypted output to a file
- Validates all config upfront with clear error messages
- Skips and annotates invalid or empty entries without aborting

---

## 🏗️ Project Structure

```
Cipher_decrypt/
├── src/
│   └── main/
│       └── java/
│           └── org/veneera/password_decrypter/
│               └── DecryptPasswords.java
├── pom.xml
├── config.properties      
└── README.md
```

---

## ⚙️ Prerequisites

- Java 11+
- Maven 3.6+
- A JKS keystore with an RSA private key

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/cipher-decrypt.git
cd cipher-decrypt
```

### 2. Build the JAR

```bash
mvn clean package
```

The output JAR will be at `target/Cipher_decrypt-1.0-SNAPSHOT.jar`.

### 3. Create `config.properties`

Create a `config.properties` file in the **same directory** you will run the JAR from:

```properties
keystore.file=keystore.jks
keystore.password=your_keystore_password
key.alias=your_key_alias
key.password=your_key_password

input.file=encrypted.txt
output.file=decrypted.txt
```

### 4. Prepare the input file

Each line in `input.file` should follow this format:

```
DB_PASSWORD=Base64EncodedEncryptedValue==
API_KEY=AnotherEncryptedValue==
EMPTY_KEY=
```

### 5. Run

```bash
java -jar target/Cipher_decrypt-1.0-SNAPSHOT.jar
```

---

## 📤 Output

Decrypted values are written to the file specified in `output.file`:

```
DB_PASSWORD=mysecretpassword
API_KEY=abc-xyz-token
EMPTY_KEY=
```

Any line that fails decryption is annotated with the error:

```
BAD_VALUE=# ERROR: Data must not be longer than 256 bytes
```

## Build
```bash
mvn clean package
# JAR will be at target/Cipher_decrypt-1.0-SNAPSHOT.jar
```

---

## 🔄 Flow

```
config.properties
      │
      ▼
 Load JKS Keystore  ──► Extract RSA Private Key
                                  │
                                  ▼
  input.txt  ──►  Base64 Decode  ──►  RSA Decrypt  ──►  output.txt
```

---

## 🔒 Security Notes

| Concern | Recommendation |
|---|---|
| Keystore password in config | Use environment variables or a secrets manager in production |
| JKS format is legacy | Migrate to PKCS12 (`.p12`) on Java 9+ |
| RSA for large data | Use AES + RSA hybrid encryption for payloads > 245 bytes |

### Migrate JKS to PKCS12

```bash
keytool -importkeystore \
  -srckeystore keystore.jks \
  -destkeystore keystore.p12 \
  -deststoretype PKCS12
```

---

## 🛠️ Built With

- Java 11
- Maven
- `javax.crypto.Cipher` — RSA decryption
- `java.security.KeyStore` — JKS keystore loading

---
