//
//  gostEncryption.hpp
//  gost28147
//
//  Created by Татару on 23.11.2022.
//

#ifndef gostEncryption_hpp
#define gostEncryption_hpp

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

enum CryptMode {
    Encrypt,
    Decrypt
};

typedef union
{
    /**
     * @brief parts 8битное представление порции данных для криптообработки
    */
    uint8_t  parts[8];
    /**
     * @brief half 32байтное представление порции данных для криптообработки
    */
    uint32_t half[2];
} Gost_Data_Part;

#define TABLE_ROW_AMOUNT        8
#define TABLE_COLUMN_AMOUNT     16
#define TABLE_SIZE              (TABLE_ROW_AMOUNT*TABLE_COLUMN_AMOUNT)
#define GOST_DEFAULT_Byte       0
#define GOST_KEY_SIZE           32
/**
  Положение накопителя N1 в объедененние данных GOST_Data_Part
*/
#define GOST_Data_Part_N1_Half 1
/**
  Положение накопителя N2 в объедененние данных GOST_Data_Part
*/
#define GOST_Data_Part_N2_Half 0

uint8_t GostEncrypt(uint8_t *data, uint32_t size, CryptMode mode, uint8_t *gostTable, uint8_t *gostKey);

void GostCryptCicleE(Gost_Data_Part *data, uint8_t *gostTable, uint32_t *gostKey);
void GostCryptCicleD(Gost_Data_Part *data, uint8_t *gostTable, uint32_t *gostKey);

#endif /* gostEncryption_hpp */
