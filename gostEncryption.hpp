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

/**
 Режимы шифрования:
 Encrypt - шифрование
 Decrypt - расшифрование
 */
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
} GostDataPart;

/**
 Количество строк таблицы
 */
#define TABLE_ROW_AMOUNT        8
/**
 Количество столбцов таблицы
 */
#define TABLE_COLUMN_AMOUNT     16
/**
 Размер таблицы
 */
#define TABLE_SIZE              (TABLE_ROW_AMOUNT*TABLE_COLUMN_AMOUNT)
/**
 Байт по умолчанию
 */
#define GOST_DEFAULT_Byte       0
/**
 Размер ключа шифрования
 */
#define GOST_KEY_SIZE           32
/**
  Положение накопителя N1 в объедененние данных GostDataPart
*/
#define GOST_Data_Part_N1_Half 1
/**
  Положение накопителя N2 в объедененние данных GostDataPart
*/
#define GOST_Data_Part_N2_Half 0

/**
 @details GostEncrypt
 Функция шифрования/расшифрования в режиме простой замены
 @param data - указатель на данные шифрования/расшифрования. Результат работы функции заносится сюда же.
 @param size - Размер данных.
 @param mode - Режим шифрования: Encrypt - шифрование, Decrypt - расшифровка.
 @param gostTable - Указатель на таблицу замены
 @param gostKey - Указатель на ключ шифрования
 */
uint8_t GostEncrypt(uint8_t *data, uint32_t size, CryptMode mode, uint8_t *gostTable, uint8_t *gostKey);

/**
@details GostCryptCicleE
Базовый алгоритм выполняющий 32шага шифрования для 64-битной порции данных
(в номенклатуре документа ГОСТ28147-89 алгоритм 32-З), обратный алгоритму 32-Р.
@param data - Указатель на данные для зашифрования в формате GostDataPart
@param gostTable - Указатель на таблицу замены
@param gostKey - 32хбитная часть ключа(СК).
*/
void GostCryptCicleE(GostDataPart *data, uint8_t *gostTable, uint32_t *gostKey);

/**
@details GostCryptCicleD
Базовый алгоритм выполняющий 32шага расшифрования для 64-битной порции данных
(в номенклатуре документа ГОСТ28147-89 алгоритм 32-Р), обратный алгоритму 32-З.
Применяется только в режиме простой замены.
@param data - Указатель на данные для зашифрования в формате GostDataPart
@param gostTable - Указатель на таблицу замены
@param gostKey - 32хбитная часть ключа(СК).
*/
void GostCryptCicleD(GostDataPart *data, uint8_t *gostTable, uint32_t *gostKey);

#endif /* gostEncryption_hpp */
