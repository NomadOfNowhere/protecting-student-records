#pragma once
#include "utils.hpp"

class ECDH {
private:
    const CryptoPP::OID curve;
    const CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh;

    struct Key {
        CryptoPP::SecByteBlock privateKey, publicKey;
    };

    static CryptoPP::OID selectCurve(const int &bits) {
        if(bits == 224) return CryptoPP::ASN1::secp224r1();
        if(bits == 384) return CryptoPP::ASN1::secp384r1();
        if(bits == 521) return CryptoPP::ASN1::secp521r1();
        return CryptoPP::ASN1::secp256r1();
    }

public:
    ECDH(): curve(CryptoPP::ASN1::secp256r1()), ecdh(curve) {}
    ECDH(const int &bits): curve(selectCurve(bits)), ecdh(curve) {}

    Key generateKeys() {
        Key kp = {
            CryptoPP::SecByteBlock(ecdh.PrivateKeyLength()),
            CryptoPP::SecByteBlock(ecdh.PublicKeyLength())
        };
        ecdh.GenerateKeyPair(rng, kp.privateKey, kp.publicKey);
        return kp;
    }

    CryptoPP::SecByteBlock computeSharedSecret(const CryptoPP::SecByteBlock &myPrivateKey, 
                                               const CryptoPP::SecByteBlock &otherPublicKey) {
        CryptoPP::SecByteBlock sharedK(ecdh.AgreedValueLength());
        
        if (!ecdh.Agree(sharedK, myPrivateKey, otherPublicKey)) {
            throw runtime_error("Fallo el acuerdo de llaves ECDH.");
        }
        return sharedK;
    }

    CryptoPP::SecByteBlock deriveKey(const CryptoPP::SecByteBlock &sharedSecret) {
        CryptoPP::SecByteBlock derivedKey(32);    // 256 bits
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        
        hkdf.DeriveKey(derivedKey, derivedKey.size(),
                       sharedSecret, sharedSecret.size(),
                       nullptr, 0, // Sin Salt
                       (const CryptoPP::byte*)"lab06", 5); // Info
                       
        return derivedKey;
    }

    void keyExchange() {
        try {
            Key alice = generateKeys();
            Key bob = generateKeys();

            // Export public keys
            string aG_str((const char*)alice.publicKey.data(), alice.publicKey.size());
            string bG_str((const char*)bob.publicKey.data(), bob.publicKey.size());
            writeFile("alice_pub_aG.txt", Base64::Encode(aG_str));
            writeFile("bob_pub_bG.txt", Base64::Encode(bG_str));
            cout << "Public keys saved in disk." << endl;

            // Compute shared secret using alice private key and bob public key
            auto sharedSecret = computeSharedSecret(alice.privateKey, bob.publicKey);
            string k_str((const char*)sharedSecret.data(), sharedSecret.size());
            cout << "Secreto compartido (K): " << Base64::Encode(k_str) << endl;

            // Derive key
            auto key = deriveKey(sharedSecret);
            string derived_str((const char*)key.data(), key.size());
            cout << "Derived key (256 bits): " << Base64::Encode(derived_str) << endl;

        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
    }
};