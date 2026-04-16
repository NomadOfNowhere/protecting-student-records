#pragma once
#include "utils.hpp"

class AES_GCM {
public:
    struct CipherData {
        string iv;         // 12 bytes
        string ciphertext; // Texto cifrado + Tag (16 bytes) al final
    };

public:
    /* Key generation (128 bits = 16 bytes) */
    string generateKey() {
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH); // 16 bytes
        rng.GenerateBlock(key, key.size());
        return string((const char*)key.data(), key.size());
    }
    void generateKeyToFile(const string &filename) {
        string key = generateKey();
        writeFile(filename, Base64::Encode(key));
        cout << "[AES-GCM] Key generated and saved in: " << filename << endl;
    }

    /* Encrypt */
    CipherData encrypt(const string &plaintext, const string &key) {
        CipherData result;

        // Generate random IV (96 bits = 12 bytes)
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE - 4); 
        rng.GenerateBlock(iv, iv.size());
        result.iv = string((const char*)iv.data(), iv.size());

        // Initialize GCM cipher
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(
            (const CryptoPP::byte*)key.data(), key.size(),
            (const CryptoPP::byte*)result.iv.data(), result.iv.size()
        );

        // Encrypt plaintext and append TAG (16 bytes) to the end of ciphertext
        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(enc,
                new CryptoPP::StringSink(result.ciphertext),
                false,          
                16   // TAG_SIZE
            )
        );

        return result;
    }
    void encryptFile(const string &keyFilename, const string &targetFilename, const string &cipherFilename) {
        // Read key from file and deserialize it
        string keyB64 = readFile(keyFilename);
        string key = Base64::Decode(keyB64);

        // Read target file and encrypt
        string plaintext = readFile(targetFilename);
        CipherData cipherData = encrypt(plaintext, key);

        // Format output: IV on line 1, Ciphertext on line 2
        string ivB64 = Base64::Encode(cipherData.iv);
        string ciphertextB64 = Base64::Encode(cipherData.ciphertext);
        
        string formattedOutput = ivB64 + "\n" + ciphertextB64;
        writeFile(cipherFilename, formattedOutput);

        cout << "[AES-GCM] Encrypted file saved in: " << cipherFilename << endl;
    }

    /* Decrypt */
    string decrypt(const CipherData &data, const string &key) {
        string plaintext;

        try {
            // // Initialize GCM decipher
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(
                (const CryptoPP::byte*)key.data(), key.size(),
                (const CryptoPP::byte*)data.iv.data(), data.iv.size()
            );

            // // Setup the decryption filter and extract the plaintext
            CryptoPP::AuthenticatedDecryptionFilter df(dec,
                new CryptoPP::StringSink(plaintext),
                CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                16   // TAG_SIZE
            );

            CryptoPP::StringSource ss(data.ciphertext, true,
                new CryptoPP::Redirector(df)
            );

            // Verify the authentication tag
            if (!df.GetLastResult()) {
                throw runtime_error("Fallo de autenticación en AES-GCM.");
            }

        } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) {
            throw runtime_error("Invalid tag or corrupt text.");
        }

        return plaintext;
    }

    void decryptFile(const string &keyFilename, const string &cipherFilename, const string &outputPlaintextFilename) {
        try {
            // Read key from file and deserialize it
            string rawKey = Base64::Decode(readFile(keyFilename));

            // Read encrypted file and parse using istringstream
            string fileContent = readFile(cipherFilename);
            istringstream iss(fileContent);
            string ivB64, ciphertextB64;
            getline(iss, ivB64);
            getline(iss, ciphertextB64);
            if (ivB64.empty() || ciphertextB64.empty()) {
                throw runtime_error("Invalid format. Expected IV and Ciphertext on separate lines.");
            }

            // Reconstruct the CipherData struct by decoding Base64
            CipherData cipherData;
            cipherData.iv = Base64::Decode(ivB64);
            cipherData.ciphertext = Base64::Decode(ciphertextB64);

            // Decrypt
            string recoveredText = decrypt(cipherData, rawKey);

            // Save recovered text
            writeFile(outputPlaintextFilename, recoveredText);
            cout << "[AES-GCM] File successfully decrypted and saved in: " << outputPlaintextFilename << "\n";

        } catch (const exception& e) {
            cerr << "[ERROR AES-GCM]: " << e.what() << "\n";
        }
    }
};