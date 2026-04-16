#pragma once
#include "utils.hpp"

// SHA-256
string SHA256Hash(const string &data) {
    CryptoPP::SHA256 hash;
    string digest;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::StringSink(digest)
        )
    );
    return Base64::Encode(digest);
}