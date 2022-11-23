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
    memcpy(messageBytes, message.data(), message.length());
    
    uint8_t keyBytes[32];
    memcpy(keyBytes, key.data(), key.length());
    uint8_t  Data_E[sizeof(messageBytes)];
    
    cout << "Незашифрованная последовательность байт" << endl;
    for(auto &b: Data_E) {
        cout << int(b) << ' ';
    }
    
    memcpy(Data_E, messageBytes, sizeof(messageBytes));
    GostEncrypt(Data_E, uint32_t(sizeof(messageBytes)), Encrypt, GostTable, keyBytes);
    
    cout << "Зашифрованная последовательность байт" << endl;
    for(auto &b: Data_E) {
        cout << int(b) << ' ';
    }
    
    GostEncrypt(Data_E, uint32_t(sizeof(Data_E)), Decrypt, GostTable, keyBytes);
    
    cout << "Расшифрованная последовательность байт" << endl;
    
    int n = int(sizeof(Data_E));
    char chars[n + 1];
    memcpy(chars, Data_E, n);
    chars[n] = '\0';
    cout << chars;
    
    
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
