/*****************************************************************************
  * @file    E:\Projetcs\C\encryptData
  * @author  Sapunov A.
  * @version -
  * @date    07.08.2017
  * @brief   Зашифрование и расшфрование данных произвольной длинны AES128.
 
  *****************************************************************************/
  
#include <stdio.h>
#include <stdlib.h>
#include "aes128.h"

#define ENCRYPTIONMODE 0   // Режим шифрования EBC (электронной кодовой книги), иначе CBC
#define OPENLENGTH     74  // Длина открытого текста (данных, которые необходимо зашифровать)
#define CIPHERLENGTH   80  // Длина шифротекста (зашифрованных данных)
//74


int getIV( void );

// Ключ шифрования
uint8_t key[4 * Nk] = {0x66, 0xa3, 0x6c, 0x8b, 0x8c, 0x54, 0x92, 0x52, 0x7c, 0xd7, 0x6b, 0x78, 0xfc, 0x67, 0x7d, 0x12};

/**
  * @brief  Зашифрование области данных
  * @param  -, однако нужно иметь указатель на область данных и их длину
  * @retval -
  */
void main( void )
{
	
	uint8_t data[] = {0xfa, 0x8d, 0x03, 0x5d, 0xde, 0x0e, 0x32, 0xfa, 0xab, 0x7c, 0xb7, 0xbf, 0xd9, 0xa0, 0x7a, 0xaf, 0x13, 0x3c, 0x86, 0xcd, 0xc6, 0xf6, 0xe6, 0x41, 0x4a, 0x12, 0xf8, 0x7c, 0x26, 0x61, 0xfc, 0x38, 0xbe, 0xd7, 0x71, 0x88, 0x32, 0xaf, 0x6c, 0xbe, 0x57, 0x89, 0x71, 0x60, 0x61, 0x48, 0x69, 0x60, 0xaa, 0x3e, 0xb6, 0xf8, 0xe6, 0x5f, 0xd1, 0x1b, 0x80, 0x57, 0xfc, 0x92, 0x6f, 0xbb, 0xb8, 0xa8, 0x71, 0x32, 0x43, 0x5a, 0x15, 0xb1, 0x56, 0x6f, 0xda, 0xc9/**/ };
	int j;
	
	
	// Отладочная информация для зашифрования
	uint8_t  *ciphertext;
	uint32_t cipherLength;
	
	ciphertext   = encryptData(data, OPENLENGTH); // Получение адреса начала области зашифрованных данных
	cipherLength = getCipherLength(OPENLENGTH);   // Длина шифротекста
	
	for(j = 0; j < cipherLength; ++j)
			printf("%x", *(ciphertext + j));
					
			
	// Отладночная информация для расшифрования
	uint8_t  *opentext;
	uint32_t opentextLength;
	
	opentext       = decryptData(ciphertext, CIPHERLENGTH);     // Получение адреса зашифрованных данных
	opentextLength = getOpentextLength(opentext, CIPHERLENGTH); // Получение длины значащих данных открытого текста
	
	printf("\n");
	for(j = 0; j < opentextLength; ++j)
			printf("%x", *(opentext + j));
									
		while(1);
}




/**
  * @brief  Получение длины шифротекста для выделения памяти под него, в соответствии с PKCS7
  * @param  len          - Длина открытого текста
  * @retval cipherLength - Длина шифротекста
  */
uint32_t getCipherLength(uint32_t len)
{
	uint32_t cipherLength        			= len;
	uint8_t  shortageUpToMultiplicity = (Nb * 4) - (len % (Nb * 4)); // Недостаток до кратности 128
	
	if(len % (Nb * 4) != 0) 																	       // Кратность 128 битам
	{
		cipherLength += shortageUpToMultiplicity; 								     // Увеличиваем длину последнего блока
	}
	else
	{
		cipherLength += (Nb * 4); 																     // Добавляем целый блок
	}
		return cipherLength;
}

/**
  * @brief  Шифрование блока данных произвольной длины
  * @param  opentext -  Указатель на начало открытого текста
  * @param  len      -  Длина открытого текста   
  * @retval Адрес первого блока памяти с зашифрованными данными
  */
uint32_t encryptData(void *opentext, uint32_t len) // Нужно здесь указывать, что ссылки на массив?
{	
	
	int w[Nb * (Nr + 1)]; // Расписание ключей
	keyExpansion(key, w); // Расширение ключа
	
	uint32_t cipherLength;
	uint32_t numberOfBlocks;
	uint8_t  *ciphertext;
	uint8_t  buff[4 * Nb];                                    	 // Буфер для блока открытых данных
	uint8_t  blockShortageUpToMultiplicity;
	int      i, j;
	
	cipherLength   = getCipherLength(len);    // Получение длины шифротекста
	numberOfBlocks = cipherLength / (Nb * 4); // Количество блоков шифротекста
	ciphertext     = malloc(cipherLength);    // Количество памяти, выделяемой под блок шифротекста, кратно 128 битам
	blockShortageUpToMultiplicity = (Nb * 4) - (len % (Nb * 4)); // Недостаток последнего блока до кратности 128
	
	
	// Идём по блокам
	for(i = 0; i < numberOfBlocks; ++i) // Шифруем каждый блок отдельно
	{
		// Для последнего блока данных осуществляем дополнение
		if(i == numberOfBlocks - 1)
		{
			if(blockShortageUpToMultiplicity == Nb * 4) // Длина данны кратна 128, то дополняем ещё одним блоком
			{
				memset(buff, 0x10, 16);                   // Заполняем последний блок 				
			}
			else // Длина данных не кратна 128, заполняем остатки последнего блока до кратности
			{
				for(j = 0; j < len % 16; ++j)
				{
					memcpy(buff, opentext, len % 16);
				}
				memset(buff + (len % 16), blockShortageUpToMultiplicity, blockShortageUpToMultiplicity);
			}
		}
		
		
		
		// Шифруем
		if(i != numberOfBlocks - 1)
		{
			encrypt_block(opentext, ciphertext, w);
		}
		else
		{
			encrypt_block(buff, ciphertext, w); // Последний блок посылаем отдельно из-за дополнения
		}
			
		// Смещение указателей на блок для работы со следующим блоком данных
		opentext   += (Nb * 4);
		ciphertext += (Nb * 4);
	}
  
	return ciphertext - cipherLength;
}


/**
  * @brief  Получение длины значимых данных в области шифротекста
  * @param  opentext - Указатель на область расшифрованных данных
  * @param  lengthOfCipher - Длина области расшифрованных данных
  * @retval Длина значимых данных в области шифротекста
  */
uint32_t getOpentextLength(uint8_t *opentext, uint32_t lengthOfCipher)
{
	uint8_t buff[4 * Nb];                                      // Для проверки на один полностью добавленный блок
	memset(buff, 0x10, Nb * 4); 
	uint8_t lastBlock[4 * Nb];                                 // Буфер для последнего блока данных
	memcpy(lastBlock, opentext + lengthOfCipher - Nb * 4, (Nb * 4)); // Заполняем буфер последним блоком
	int i, j;
	
	// Избавляемся от байт дополнения
		if(!memcmp(lastBlock, buff, (Nb * 4)))
			return lengthOfCipher - (Nb * 4);
		else
			return  lengthOfCipher - lastBlock[15];
}


/*
  * @brief  Расшифрование области данных
  * @param  ciphertext - указатель на область зашифрованных данных
  * @param  lengthOfCipher - Длину зашифрованных данных
  * @retval Адрес начала блока расшифрованных данных
  */
uint32_t decryptData(void *ciphertext, uint32_t lengthOfCipher)
{	
	int w[Nb * (Nr + 1)];                       // Расписание ключей
	keyExpansion(key, w);                       // Расширение ключа
	
	uint32_t numberOfBlocks;                    // Количество блоков шифротекста
	uint8_t *opentext;
	uint8_t buff[4 * Nb];                       // Буфер для блока открытых данных
	int i, j;  
	
	opentext = malloc(lengthOfCipher);          // Количество памяти под блок открытого текста кратно 128 битам
	numberOfBlocks = lengthOfCipher / (Nb * 4); // Количество блоков шифротекста
	
	// Расшифровываем
	for(i = 0; i < numberOfBlocks; ++i)
	{
			decrypt_block(ciphertext, opentext, w);
			
			// Смещение указателей для работы со следующим блоком данных
			opentext   += (Nb * 4);
			ciphertext += (Nb * 4);
	} 	
	return opentext - lengthOfCipher;
}
