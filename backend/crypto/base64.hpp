#pragma once
#include "utils.hpp"

// Base64
class Base64 {
public:
    static inline string Encode(const string &data) {
        string encoded;
        CryptoPP::StringSource(data, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded),
                false   // disable line breaks
            )
        );   
        return encoded;
    }
    static inline string Decode(const string &data) {
        string decoded; 
        CryptoPP::StringSource(data, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded)
            )
        );
        return decoded;
    }
};