#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/base64.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/integer.h>
#include <string>
#include <stdexcept>
/*
 * Compile: 
 *    g++ utils.cpp -o utils -std=c++20 -lcryptopp -O3
 * -pthread
 */
using namespace std;
namespace Crypto = CryptoPP;
Crypto::AutoSeededRandomPool rng;

// SHA-256
string SHA256Hash(const string &data) {
    Crypto::SHA256 hash;
    string digest;

    Crypto::StringSource ss(data, true,
        new Crypto::HashFilter(hash,
            new Crypto::HexEncoder(
                new Crypto::StringSink(digest)
            )
        )
    );
    return digest;
}

// AES-GCM 128 bit
// key: 128-bits (16b), iv: 96-bits(12b), tag: 128-bits(16b)
class AES_GCM {
private:
    string data;   // ciphertext + tag / recovered text
    string iv;
public:
    void Encrypt(const string &plaintext, const string &key) {
        // Random IV
        Crypto::SecByteBlock iv(Crypto::AES::BLOCKSIZE - 4);   // 12 bytes
        rng.GenerateBlock(iv, iv.size());

        Crypto::GCM<Crypto::AES>::Encryption enc;
        enc.SetKeyWithIV(
            (const Crypto::byte*)key.data(), key.size(),
            iv.data(), iv.size()
        );

        // TAG_SIZE = 16 bytes; append at end of ciphertext
        Crypto::StringSource ss(plaintext, true,
            new Crypto::AuthenticatedEncryptionFilter(enc,
                new Crypto::StringSink(data),
                false,          
                16              // TAG_SIZE
            )
        );

        this->iv = string((const char*)iv.data(), iv.size());
    }

    void Decrypt(const string &key, const string &iv) {
        string ciphertext = data;

        try {
            Crypto::GCM<Crypto::AES>::Decryption dec;
            dec.SetKeyWithIV(
                (const Crypto::byte*)key.data(), key.size(),
                (const Crypto::byte*)iv.data(),  iv.size()
            );

            Crypto::AuthenticatedDecryptionFilter df(dec,
                new Crypto::StringSink(data),
                Crypto::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                16   // TAG_SIZE
            );

            Crypto::StringSource ss(ciphertext, true,
                new Crypto::Redirector(df)
            );

            if (!df.GetLastResult())
                throw std::runtime_error("AES-GCM: autenticación fallida");

        } catch (const Crypto::HashVerificationFilter::HashVerificationFailed&) {
            throw std::runtime_error("AES-GCM: tag inválido");
        }
    }
};


// ECDSA signature (secp256k1 curve)
class ECDSA {
private:
    Crypto::ECDSA<Crypto::ECP, Crypto::SHA256>::PrivateKey k_priv;
    Crypto::ECDSA<Crypto::ECP, Crypto::SHA256>::PublicKey k_pub;

public:
    void GenerateKeypair() {
        k_priv.Initialize(rng, Crypto::ASN1::secp256k1());
        k_priv.MakePublicKey(k_pub);
    }
    string Sign(const string &message) {
        string signature;
        Crypto::ECDSA<Crypto::ECP, Crypto::SHA256>::Signer signer(k_priv);
        Crypto::StringSource ss(message, true,
            new Crypto::SignerFilter(rng, signer,
                new Crypto::StringSink(signature)
            )
        );
        return signature;
    }
    bool Verify(const string &message, const string &signature) {
        bool result = false;
        Crypto::ECDSA<Crypto::ECP, Crypto::SHA256>::Verifier verifier(k_pub);
        Crypto::StringSource ss(signature + message, true,
            new Crypto::SignatureVerificationFilter(verifier,
                new Crypto::ArraySink((Crypto::byte*)&result, sizeof(result)),
                    Crypto::SignatureVerificationFilter::PUT_RESULT |
                    Crypto::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
            )
        );
        return result;
    }

    // Serialize key priv to base64
    // string PrivKeyToBase64() {

    // }

};


int main() {
    cout << "xd" << endl;
    return 0;
}