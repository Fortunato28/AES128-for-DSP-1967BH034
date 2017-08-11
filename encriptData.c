#include <stdio.h>
#include <stdlib.h>
#include "aes128.h"

#define LENGTH 77 // длина открытого текста
//74

int encriptData(void *opentext, int len); // Хз, как тут с типами указателей
int getCipherLength(int len);
 

/**
  * @brief  Зашифрование области данных
  * @param  -, однако нужно иметь указатель на область данных и их длину
  * @retval -
  */
void main( void )
{
 	uint8_t data[] = {0xfa, 0x8d, 0x03, 0x5d, 0xde, 0x0e, 0x32, 0xfa, 0xab, 0x7c, 0xb7, 0xbf, 0xd9, 0xa0, 0x7a, 0xaf, 0x13, 0x3c, 0x86, 0xcd, 0xc6, 0xf6, 0xe6, 0x41, 0x4a, 0x12, 0xf8, 0x7c, 0x26, 0x61, 0xfc, 0x38, 0xbe, 0xd7, 0x71, 0x88, 0x32, 0xaf, 0x6c, 0xbe, 0x57, 0x89, 0x71, 0x60, 0x61, 0x48, 0x69, 0x60, 0xaa, 0x3e, 0xb6, 0xf8, 0xe6, 0x5f, 0xd1, 0x1b, 0x80, 0x57, 0xfc, 0x92, 0x6f, 0xbb, 0xb8, 0xa8, 0x71, 0x32, 0x43, 0x5a, 0x15, 0xb1, 0x56, 0x6f, 0xda, 0xc9,/**/ 0x34, 0xd4, 0x2c};
 	int len = LENGTH, j;
	uint8_t *ciphertext;
	
	int cipherLength = getCipherLength(len); // Длина шифротекста
	ciphertext = encriptData(data, len);
	
	for(j = 0; j < cipherLength; ++j)
			printf("%x\n", *(ciphertext + j));
	
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
	uint8_t key[4 * Nk] = {0x66, 0xa3, 0x6c, 0x8b, 0x8c, 0x54, 0x92, 0x52, 0x7c, 0xd7, 0x6b, 0x78, 0xfc, 0x67, 0x7d, 0x12};
	int w[Nb * (Nr + 1)]; // Расписание ключей
	keyExpansion(key, w); // Расширение ключа
	
	uint8_t *ciphertext;
	int i, j;
	uint8_t buff[4 * Nb]; // Буфер для блока открытых данных
	uint8_t blockShortageUpToMultiplicity = 16 - (len % 16); // Недостаток последнего блока до кратности 128
	
	int cipherLength = getCipherLength(len); // Получение длины шифротекста
	int numberOfBlocks = cipherLength / 16; // Количество блоков шифротекста
	ciphertext = malloc(cipherLength); // Количество памяти, выделяемой под блок шифротекста, кратно 128 битам
	

	// Идём по блокам
	for(i = 0; i < numberOfBlocks; ++i) // Шифруем каждый блок отдельно
	{
		// Для последнего блока данных осуществляем дополнение
		if(i == numberOfBlocks - 1)
		{
			if(blockShortageUpToMultiplicity == 16) // Длина сообщения кратна 128
			{
				memset(buff, 0x10, 16); // Заполняем последний блок 				
			}
			else
			{
				for(j = 0; j < len % 16; ++j)
				{
					memcpy(buff, opentext, len % 16);
					//memset(buff + j, *(uint8_t *)(opentext + j), len % 16);
				}
				memset(buff + (len % 16), blockShortageUpToMultiplicity, blockShortageUpToMultiplicity); // Заполняем остатки блока
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






















