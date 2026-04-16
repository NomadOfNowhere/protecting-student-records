#include "utils.hpp"

// ECDSA signature (secp256r1 curve)
class ECDSA {
private:
    struct Key {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;  
    };

public:
    /* Key generation */
    Key keyGeneration() {
        Key key;
        key.privKey.Initialize(rng, CryptoPP::ASN1::secp256r1());
        key.privKey.MakePublicKey(key.pubKey);
        return key;
    }
    void keyGenerationToFiles(const string &privFilename, const string &pubFilename) {
        // Generate keys and serialize them
        auto key = keyGeneration();
        string privKeyStr = serializePrivateKey(key.privKey);
        string pubKeyStr = serializePublicKey(key.pubKey);
        
        // Save keys to files
        writeFile(privFilename, Base64::Encode(privKeyStr));
        writeFile(pubFilename, Base64::Encode(pubKeyStr));

        cout << "[ECDSA] Keys generated successfully" << endl;
    }

    /* Signature generation */
    string sign
    (
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey &privKey, 
        const string &message
    ) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privKey);
        string signature;
        
        CryptoPP::StringSource ss(message, true,
            new CryptoPP::SignerFilter(rng, signer, 
                new CryptoPP::StringSink(signature)
            )
        );
        return signature;
    }
    string signFile(const string &privFilename, const string &targetFilename, const string &signFilename) {
        // Read private key from file and deserialize it
        string privB64 = readFile(privFilename);
        auto privKey = deserializePrivateKey(Base64::Decode(privB64));

        string message = readFile(targetFilename);

        // Generate signature (r || s) and split into independent r and s
        string signature = sign(privKey, message);
        size_t half = signature.size() / 2;
        string r = signature.substr(0, half);
        string s = signature.substr(half);

        // Serialize signature (r,s) and save to file
        string signatureB64 = Base64::Encode(r) + "\n" + Base64::Encode(s);
        writeFile(signFilename, signatureB64);
        
        cout << "[ECDSA] Signature (r, s) saved in file: " << signFilename << "\n";
        return signatureB64;
    }

    /* Signature verification */
    bool verify
    (
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey &pubKey,
        const string &message, 
        const string &signature
    ) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(pubKey);
        bool isValid = false;
        
        CryptoPP::StringSource ss(signature + message, true,
            new CryptoPP::SignatureVerificationFilter(verifier,
                new CryptoPP::ArraySink((CryptoPP::byte*)&isValid, sizeof(isValid)),
                CryptoPP::SignatureVerificationFilter::PUT_RESULT | 
                CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
            )
        );
        return isValid;
    }
    bool verifyFile(const string &pubFilename, const string &targetFilename, const string &signFilename) {
        try {
            string pubB64 = readFile(pubFilename);
            string message = readFile(targetFilename);
            string signB64 = readFile(signFilename);

            // Deserialize public key and concatenate signature (r || s)
            auto pubKey = deserializePublicKey(Base64::Decode(pubB64));
            istringstream iss(signB64);
            string r_b64, s_b64;
            getline(iss, r_b64);
            getline(iss, s_b64);
            if (r_b64.empty() || s_b64.empty()) {
                throw runtime_error("Invalid signature format. Expected r and s on separate lines.");
            }
            string signature = Base64::Decode(r_b64) + Base64::Decode(s_b64);

            return verify(pubKey, message, signature);
        } catch (const exception& e) {
            cerr << "[ERROR]: " << e.what() << endl;
            return false;
        }
    }

    
    /* Serialize/Deserialize functions */
    string serializePrivateKey(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey &privKey) {
        string key;
        privKey.Save(CryptoPP::StringSink(key).Ref());
        return key;
    }
    string serializePublicKey(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey &pubKey) {
        string key;
        pubKey.Save(CryptoPP::StringSink(key).Ref());
        return key;
    }
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey deserializePrivateKey(const string &key) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
        privKey.Load(CryptoPP::StringStore(key).Ref());
        return privKey;
    }
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey deserializePublicKey(const string &key) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
        pubKey.Load(CryptoPP::StringStore(key).Ref());
        return pubKey;
    }
};
