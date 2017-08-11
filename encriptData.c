#include <stdio.h>
#include <stdlib.h>
#include "aes128.h"

#define OPENLENGTH 74 // Длина открытого текста
#define CIPHERLENGTH 80 // Длина шифроткста
//74


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
	
	
	// Отладочная инфа для зашифрования
	uint8_t *ciphertext;
	int len = OPENLENGTH;
	int cipherLength = getCipherLength(len); // Длина шифротекста
	ciphertext = encriptData(data, len);
	
	for(j = 0; j < cipherLength; ++j)
			printf("%x", *(ciphertext + j));
			
	// Отладночная инфа для расшифрования
	uint8_t *opentext;
	int lengthOfCipher = CIPHERLENGTH;
	opentext = decriptData(ciphertext, lengthOfCipher);
	int opentextLength = getOpentextLength(opentext, lengthOfCipher); // Нужно вызывать получения открытого текста
	
	printf("\n Length of opentext = %d\n", opentextLength);
	for(j = 0; j < opentextLength; ++j)
			printf("%x", *(opentext + j));
	
		while(1);
}


/**
  * @brief  Получение длины шифротекста для выделения памяти под него, в соответствии с PKCS7
  * @param  Длина открытого текста len
  * @retval Длина шифротекста
  */
int getCipherLength(int len)
{
	int cipherLength = len;
	int shortageUpToMultiplicity = 16 - (len % 16); // Недостаток до кратности 128
	
	if(len % 16 != 0) // Кратность 128 битам
	{
		cipherLength += shortageUpToMultiplicity; // Увеличиваем длину последнего блока
	}
	else
	{
		cipherLength += 16; // Добавляем целый блок, если длина сообщения кратна 128 битам
	}
		return cipherLength;
}


/**
  * @brief  Шифрование блока данных произвольной длины
  * @param  Указатель на начало открытого текста opentext, длина открытого текста len
  * @retval Указатель на блок памяти с зашифрованными данными
  */
int encriptData(void *opentext, int len) // нужно здесь указывать, что ссылки на массив?
{
	int w[Nb * (Nr + 1)]; // Расписание ключей
	keyExpansion(key, w); // Расширение ключа
	
	uint8_t *ciphertext;
	int i, j;
	uint8_t buff[4 * Nb]; // Буфер для блока открытых данных
	uint8_t blockShortageUpToMultiplicity = 16 - (len % 16); // Недостаток последнего блока до кратности 128
	
	int cipherLength   = getCipherLength(len); // Получение длины шифротекста
	int numberOfBlocks = cipherLength / 16;    // Количество блоков шифротекста
	ciphertext         = malloc(cipherLength); // Количество памяти, выделяемой под блок шифротекста, кратно 128 битам
	

	// Идём по блокам
	for(i = 0; i < numberOfBlocks; ++i) // Шифруем каждый блок отдельно
	{
		// Для последнего блока данных осуществляем дополнение
		if(i == numberOfBlocks - 1)
		{
			if(blockShortageUpToMultiplicity == 16) // Длина данны кратна 128, то дополняем ещё одним блоком
			{
				memset(buff, 0x10, 16); // Заполняем последний блок 				
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
			encript_block(opentext, ciphertext, w);
		}
		else
		{
			encript_block(buff, ciphertext, w); // Последний блок посылаем отдельно из-за дополения
		}
		
		/*for(j = 0; j < 16; ++j)
		{
			if(i != numberOfBlocks - 1)
				printf("%x", *(uint8_t *)opentext++);
			else
				printf("%x", *(buff + j));
		}
		
			printf("\ncipherLength = %d\n", cipherLength);
			
		for(j = 0; j < 16; ++j)
			printf("%x", *(uint8_t *)ciphertext++);
			
		printf("\ncipherLength = %d\n", cipherLength);*/
			
		opentext += 16; // Смещение указателей для работы со следующим блоком данных
		ciphertext += 16;
	}
	return ciphertext - cipherLength;
}


/**
  * @brief  Получение длины значимых данных в области шифротекста
  * @param  Указатель на область зашифрованных данных и их длину
  * @retval Длина значимых данных в области шифротекста
  */
int getOpentextLength(uint8_t *opentext, int lengthOfCipher)
{
	uint8_t buff[4 * Nb]; // Для проверки на один полностью добавленный блок
	memset(buff, 0x10, 16); // Для проверки на один полностью добавленный блок
	uint8_t lastBlock[4 * Nb]; // Буфер для последнего блока данных
	memcpy(lastBlock, opentext + lengthOfCipher - 16, 16); // Заполняем буфер последним блоком
	int i, j;
	
	/*
	for(j = 0; j < 16; ++j)
		printf("%x\n", lastBlock[j]);
		
	for(j = 0; j < 16; ++j)
		printf("%x\n", buff[j]);
		*/
	
		if(!memcmp(lastBlock, buff, 16))
			return lengthOfCipher - 16;
		else
			return  lengthOfCipher - lastBlock[15];
		
	return 0;
}


/*
  * @brief  Расшифрование области данных
  * @param  -, однако нужно иметь указатель на область зашифрованных данных и их длину
  * @retval -
  */
int decriptData(void *ciphertext, int lengthOfCipher)
{
	int w[Nb * (Nr + 1)]; // Расписание ключей
	keyExpansion(key, w); // Расширение ключа
	
	uint8_t *opentext;
	opentext = malloc(lengthOfCipher); // Количество памяти под блок открытого текста кратно 128 битам
	
	int i, j;
	uint8_t buff[4 * Nb]; // Буфер для блока открытых данных
	int numberOfBlocks = lengthOfCipher / 16; // Количество блоков шифротекста
	//uint8_t blockShortageUpToMultiplicity = 16 - (len % 16); // Недостаток последнего блока до кратности 128
	
	
	// Расшифровываем
	for(i = 0; i < numberOfBlocks; ++i)
	{
			decript_block(ciphertext, opentext, w);
			
			// Смещение указателей для работы со следующим блоком данных
			ciphertext += 16;
			opentext += 16;
	} 
	
	return opentext - lengthOfCipher;
}





















