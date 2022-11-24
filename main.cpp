//
//  main.cpp
//  gost28147
//
//  Created by Татару on 23.11.2022.
//

#include "gostEncryption.hpp"
#include <iostream>
#include <cstddef>
#include <cstring>
#include <stdlib.h>

uint8_t GostTable[TABLE_SIZE] {
    0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01,
    0x06, 0x08, 0x02, 0x03, 0x09, 0x0A, 0x05, 0x0C, 0x01, 0x0E, 0x04, 0x07, 0x0B, 0x0D, 0x00, 0x0F,
    0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00,
    0x0C, 0x08, 0x02, 0x01, 0x0D, 0x04, 0x0F, 0x06, 0x07, 0x00, 0x0A, 0x05, 0x03, 0x0E, 0x09, 0x0B,
    0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C,
    0x05, 0x0D, 0x0F, 0x06, 0x09, 0x02, 0x0C, 0x0A, 0x0B, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0E, 0x00,
    0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07,
    0x01, 0x07, 0x0E, 0x0D, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0F, 0x0A, 0x06, 0x09, 0x0C, 0x0B, 0x02
};

std::string defaultKey = "that_key_can_help_you_to_hide_ms";

int main(int argc, const char * argv[]) {
    std::string message;
    std::string key;
    bool isDataCorrect = false;
    
    while (!isDataCorrect) {
        std::cout << "Enter message to crypt (In English)" << std::endl;
        std::getline(std::cin, message);
        std::cout << std::endl;
        
        if(message.length() % 8 != 0) {
            std::cout << "The message length must be a multiple of 8 bits";
            continue;
        }
        
        isDataCorrect = true;
    }
    isDataCorrect = false;
    while (!isDataCorrect) {
        std::cout << "Enter the encryption key (In English, length = 32)" << std::endl;
        std::getline(std::cin, key);
        std::cout << std::endl;
        
        if(key == "\n")
            key = defaultKey;
        else if(key.length() != 32) {
            std::cout << "The key length must be 32 bits";
            continue;
        }
        
        isDataCorrect = true;
    }
    
    uint8_t messageBytes[message.length()];
    memcpy(messageBytes, message.data(), message.length());
    
    uint8_t keyBytes[32];
    memcpy(keyBytes, key.data(), key.length());
    
    uint8_t Data_E[sizeof(messageBytes)];   
    
    memcpy(Data_E, messageBytes, sizeof(messageBytes));
    GostEncrypt(Data_E, uint32_t(sizeof(messageBytes)), Encrypt, GostTable, keyBytes);
    
    std::cout << "Encrypted byte sequence" << std::endl;
    for(auto &b: Data_E) {
        std::cout << int(b) << ' ';
    }
    std::cout << std::endl;
    std::cout << std::endl;
    
    GostEncrypt(Data_E, uint32_t(sizeof(Data_E)), Decrypt, GostTable, keyBytes);
    
    std::cout << "Decrypted message" << std::endl;
    
    for(auto &b: Data_E) {
        std::cout << b;
    }
    std::cout << std::endl;

    std::cout << "You can close the program now! Press any key!";
    std::cin.get();
    
    return 0;
}
