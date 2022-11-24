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

using namespace::std;

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

uint8_t GOST_Key_d[GOST_KEY_SIZE] = {
        0x04, 0x75, 0xF6, 0xE0, 0x50, 0x38, 0xFB, 0xFA, 0xD2, 0xC7, 0xC3, 0x90, 0xED, 0xB3, 0xCA, 0x3D,
        0x15, 0x47, 0x12, 0x42, 0x91, 0xAE, 0x1E, 0x8A, 0x2F, 0x79, 0xCD, 0x9E, 0xD2, 0xBC, 0xEF, 0xBD
};
uint8_t Data_O[24] = {
    0x6A, 0xDB, 0x6E, 0xC5, 0x3E, 0xC6, 0x45, 0xA4, 0x70, 0xA8, 0x22, 0xB8, 0x94, 0xA7, 0xFE, 0x28,
    0x38, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

string defaultKey = "that_key_can_help_you_to_hide_ms";

int main(int argc, const char * argv[]) {
    string message;
    string key;
    
    cout << "Введите сообщение для шифрования" << endl;
    cin >> message;
    
    if(message.length() % 8 != 0) {
        cout << "Длинна сообщения должна быть кратной 8 бит";
        //continue;
    }
        
    
    cout << "Введите ключ шифрования" << endl;
    cin >> key;
    
    if(key == "\n")
        key = defaultKey;
    else if(key.length() != 32) {
        cout << "Длинна ключа должна быть 32 бит";
        //continue;
    }
    
    uint8_t messageBytes[message.length()];
    memcpy(messageBytes, message.data(), message.size());
    
    uint8_t keyBytes[32];
    memcpy(keyBytes, key.data(), key.length());
    
    uint8_t Data_E[sizeof(messageBytes)];
    //uint8_t Data_E[sizeof(Data_O)];
    memcpy(Data_E, messageBytes, sizeof(messageBytes));
    
    cout << "Незашифрованная последовательность байт" << endl;
    for(auto &b: Data_E) {
        cout << int(b) << ' ';
    }
    cout << endl;
    
    memcpy(Data_E, messageBytes, sizeof(messageBytes));
    GostEncrypt(Data_E, uint32_t(sizeof(messageBytes)), Encrypt, GostTable, keyBytes);
    
    cout << "Зашифрованная последовательность байт" << endl;
    for(auto &b: Data_E) {
        cout << int(b) << ' ';
    }
    cout << endl;
    
    GostEncrypt(Data_E, uint32_t(sizeof(Data_E)), Decrypt, GostTable, keyBytes);
    
    cout << "Расшифрованная последовательность байт" << endl;
    for(auto &b: Data_E) {
        cout << int(b) << ' ';
    }
    cout << endl;
    
    /*char str[(sizeof Data_E) + 1];
    memcpy(str, Data_E, sizeof Data_E);
    str[sizeof(Data_E)] = 0;
    printf("%s\n", str);*/
    
    /*if (memcmp(Data_C_S_Et,Data_E,sizeof(Data_E)) <= 0)
    {
        printf("Simple replacement encryption test failed\r\n");
    } else
    {
        printf("Simple replacement encryption test passed\r\n");
    }
    GostEncrypt(Data_E, sizeof(Data_E), Decrypt, Gost_Table, GostKey);
    if (memcmp(Data_O,Data_E,sizeof(Data_E)) <= 0)
    {
        printf("Simple replacement decryption test failed\r\n");
    } else
    {
        printf("Simple decryption test passed\r\n");
    }*/
    
    return 0;
}
