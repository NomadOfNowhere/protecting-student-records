#pragma once
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/base64.h>
#include <cryptopp/dh.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/dh2.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/integer.h>

/*
 * Compile: 
 *    g++ utils.cpp -o utils -std=c++20 -pthread -lcryptopp -O3
*/

using namespace std;
inline CryptoPP::AutoSeededRandomPool rng;
#define endl "\n"

inline void writeFile(const string &filename, const string &content) {
    ofstream ofs(filename);
    if (!ofs) throw runtime_error("Cannot write file: " + filename);
    ofs << content;
}

inline string readFile(const string& filename) {
    ifstream ifs(filename);
    if (!ifs) throw runtime_error("Cannot read file: " + filename);
    return string(istreambuf_iterator<char>(ifs),
                       istreambuf_iterator<char>());
}

#include "base64.hpp"
#include "sha256.hpp"
#include "aes128.hpp"
#include "ecdh.hpp"
#include "ecdsa.hpp"
