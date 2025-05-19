 RSA Digital Signature Implementation APP 1
 // Level 3 - App 1: Signer, sends data to tampering proxy
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <cryptlib.h>
#include <rsa.h>
#include <osrng.h>
#include <hex.h>
#include <files.h>
#include <base64.h>
#include <pssr.h>
#include <sha.h>
#pragma comment(lib, "ws2_32.lib")

using namespace std;
using namespace CryptoPP;

void generateKeys(const string& privFile, const string& pubFile) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
    privateKey.Save(FileSink(privFile.c_str()).Ref());
    publicKey.Save(FileSink(pubFile.c_str()).Ref());
}

RSA::PrivateKey loadPrivateKey(const string& filename) {
    RSA::PrivateKey key;
    key.Load(FileSource(filename.c_str(), true).Ref());
    return key;
}

RSA::PublicKey loadPublicKey(const string& filename) {
    RSA::PublicKey key;
    key.Load(FileSource(filename.c_str(), true).Ref());
    return key;
}

string signMessage(const string& message, RSA::PrivateKey& key) {
    AutoSeededRandomPool rng;
    string signature;
    RSASS<PSS, SHA256>::Signer signer(key);
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new HexEncoder(new StringSink(signature))
        )
    );
    return signature;
}

string readKeyFile(const string& filename) {
    ifstream file(filename);
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    string privFile = "private.key";
    string pubFile = "public.key";

    generateKeys(privFile, pubFile);
    RSA::PrivateKey privKey = loadPrivateKey(privFile);
    RSA::PublicKey pubKey = loadPublicKey(pubFile);

    string message;
    cout << "Enter message to sign: ";
    getline(cin, message);

    string signature = signMessage(message, privKey);
    string pubKeyStr = readKeyFile(pubFile);

    string data = message + "\n" + signature + "\n" + pubKeyStr;

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(5002);
    inet_pton(AF_INET, "127.0.0.1", &proxyAddr.sin_addr);

    connect(sock, (sockaddr*)&proxyAddr, sizeof(proxyAddr));
    send(sock, data.c_str(), data.length(), 0);

    cout << "Data sent to tampering proxy.\n";
    closesocket(sock);
    WSACleanup();
    return 0;
}
