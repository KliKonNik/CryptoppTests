#include <iostream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
//#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
//#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/rijndael.h>

#include <libpq/libpq.h>

using std::cout;
using std::endl;
using std::string;

int main(int argc, char* argv[])
{
    /*CryptoPP testing*/
    using namespace CryptoPP;

    cout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
    cout << "key length (min): " << AES::MIN_KEYLENGTH << endl;
    cout << "key length (max): " << AES::MAX_KEYLENGTH << endl;
    cout << "block size: " << AES::BLOCKSIZE << endl;

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string plain = "CBC Mode Test";
    std::string cipher, recovered;

    std::cout << "plain text: " << plain << std::endl;

    //*********************************

    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    //*********************************

    std::cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    //*********************************

    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    cout << "Plain text:\n"           << plain     << endl << endl;
    cout << "Encpypted plain text:\n" << cipher    << endl << endl;
    cout << "Decpypted plain text:\n" << recovered << endl;
    
    /**/

    cout << endl;

    return 0;
}