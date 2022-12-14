//
//  gostEncryption.cpp
//  gost28147
//
//  Created by Татару on 23.11.2022.
//

#include "gostEncryption.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <bit>
#include <cstdint>
#include <iostream>
#include <memory.h>

#define _Min(x,y)           (x > y ? y : x)
#define _SWAPW32(W)         ((W>>24) | (W<<24) | ((W>>8)&0xFF00) | ((W<<8)&0xFF0000))

/**
@details GostCryptStep
Выполняет простейший шаг криптопреобразования(шифрования и расшифрования) ГОСТ28147-89
@param data - Указатель на данные для зашифрования в формате GOST_Data_Part
@param gostTable - Указатель на таблицу замены
@param gostKey - 32хбитная часть ключа.
@param last - Является ли шаг криптопреобразования последним? Если да(true)-
результат будет занесен в 32х битный накопитель  N2, в противном случае предыдущие значение N1
сохраняется в N2, а результат работы будет занесен в накопитель N1.
*/
void GostCryptStep(GostDataPart *data, uint8_t *gostTable, uint32_t gostKey, bool last);

uint8_t GostEncrypt(uint8_t *data, uint32_t size, CryptMode mode, uint8_t *gostTable, uint8_t *gostKey) {
    
    uint8_t currentPartSize;
    GostDataPart dataPart;
    uint32_t *keyPart = (uint32_t *) gostKey;
    
    while (size != 0) {
        currentPartSize = _Min(sizeof(GostDataPart), size);
        memset(&dataPart, GOST_DEFAULT_Byte, sizeof(dataPart));
        memcpy(&dataPart, data, currentPartSize);
        
        dataPart.half[GOST_Data_Part_N2_Half]=_SWAPW32(dataPart.half[GOST_Data_Part_N2_Half]);
        dataPart.half[GOST_Data_Part_N1_Half]=_SWAPW32(dataPart.half[GOST_Data_Part_N1_Half]);

        if(mode == Encrypt) {
            GostCryptCicleE(&dataPart, gostTable, keyPart);
        } else {
            GostCryptCicleD(&dataPart, gostTable, keyPart);
        }
        
        dataPart.half[GOST_Data_Part_N2_Half]=_SWAPW32(dataPart.half[GOST_Data_Part_N2_Half]);
        dataPart.half[GOST_Data_Part_N1_Half]=_SWAPW32(dataPart.half[GOST_Data_Part_N1_Half]);
        memcpy(data, &dataPart, currentPartSize);
        data += currentPartSize;
        size -= currentPartSize;
    }
    
    return 0;
}

void GostCryptCicleE(GostDataPart *data, uint8_t *gostTable, uint32_t *gostKey){
    uint8_t k,j;
    uint32_t *tempKey = gostKey;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0

    for(k=0;k<3;k++)
    {
        for (j=0;j<8;j++)
        {
            GostCryptStep(data, gostTable, *gostKey, false);
            gostKey++;
        }
        gostKey = tempKey;
    }

    gostKey+=7;//K7

    for (j=0;j<7;j++)
    {
        GostCryptStep(data, gostTable, *gostKey, false);
        gostKey--;
    }
    GostCryptStep(data, gostTable, *gostKey, true);
}

void GostCryptCicleD(GostDataPart *data, uint8_t *gostTable, uint32_t *gostKey)
{
    uint8_t k,j;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0
    for (j=0;j<8;j++)
    {
        GostCryptStep(data, gostTable, *gostKey, false) ;
        gostKey++;
    }
//GOST_Key offset =  GOST_Key + _GOST_32_3P_CICLE_ITERS_J
    for(k=0;k<2;k++)
    {
        for (j=0;j<8;j++)
        {
            gostKey--;
            GostCryptStep(data, gostTable, *gostKey, false) ;
        }
        gostKey+=8;
    }
    for (j=0;j<7;j++)
    {
        gostKey--;
        GostCryptStep(data, gostTable, *gostKey, false) ;
    }
    gostKey--;
    GostCryptStep(data, gostTable, *gostKey, true) ;

}


void GostCryptStep(GostDataPart *data, uint8_t *gostTable, uint32_t gostKey, bool last)
{
    typedef  union
    {
        uint32_t full;
        uint8_t parts[TABLE_ROW_AMOUNT / 2];
    } GOSTDataPartSum;
    GOSTDataPartSum S;
    uint8_t m;
    uint8_t tmp;
    //N1=Lo(DATA); N2=Hi(DATA)

    S.full = (uint32_t)((*data).half[GOST_Data_Part_N1_Half] + gostKey) ;//S=(N1+X)mod2^32

    for(m=0; m<(TABLE_ROW_AMOUNT/2); m++)
    {
        //S(m)=H(m,S)
        tmp = S.parts[m];
        S.parts[m] = *(gostTable + (tmp&0x0F));//Low value
        gostTable += TABLE_COLUMN_AMOUNT;//next line in table
        S.parts[m] |= (*(gostTable + ((tmp&0xF0)>>4)))<<4;//Hi value
        gostTable += TABLE_COLUMN_AMOUNT;//next line in table

    }
    S.full = (*data).half[GOST_Data_Part_N2_Half]^_lrotl(S.full, 11);//S=Rl(11,S); rol S,11 //S XOR N2
    if (last)
    {
        (*data).half[GOST_Data_Part_N2_Half] = S.full; //N2=S
    }else
    {
        (*data).half[GOST_Data_Part_N2_Half] = (*data).half[GOST_Data_Part_N1_Half];//N2=N1
        (*data).half[GOST_Data_Part_N1_Half] = S.full;//N1=S
    }
}
