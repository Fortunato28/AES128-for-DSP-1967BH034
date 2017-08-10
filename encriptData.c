#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "aes128.h"

#define LENGTH 80 // длина открытого текста

void encriptData(void *opentext, int len, void *ciphertext); // Хз, как тут с типами указателей
 
void main( void )
{
	uint8_t data[] = {0xfa, 0x8d, 0x03, 0x5d, 0xde, 0x0e, 0x32, 0xfa, 0xab, 0x7c, 0xb7, 0xbf, 0xd9, 0xa0, 0x7a, 0xaf, 0x27, 0x92, 0x80, 0x67, 0x01, 0x73, 0x26, 0x25, 0x40, 0x57, 0x62, 0x86, 0x21, 0x52, 0x49, 0x24, 0x04, 0x26, 0x73, 0x28, 0x32, 0x17, 0x65, 0x10, 0x27, 0x92, 0x45, 0x92, 0x50, 0x92, 0x76, 0x83, 0x72, 0x65, 0x40, 0x27, 0x96, 0x21, 0x67, 0x62, 0x17, 0x96, 0x52, 0x49, 0x25, 0x78, 0x76, 0x65, 0x42, 0x04, 0x62, 0x97, 0x84, 0x94, 0x23, 0x49, 0x09, 0x27};
	int len = LENGTH;
	uint8_t *ciphertext;
	
	
	encriptData(data, len, ciphertext);
	
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
  * @param  Указатель на начало открытого текста opentext, длина открытого текста len, 
  					указатель на начало области для записи шифротекста ciphertext, ключ шифрования key
  * @retval Блок памяти с зашифрованными данными
  */
void encriptData(void *opentext, int len, void *ciphertext) // нужно здесь указывать, что ссылки на массив?
{
	uint8_t key[4 * Nk] = {0x66, 0xa3, 0x6c, 0x8b, 0x8c, 0x54, 0x92, 0x52, 0x7c, 0xd7, 0x6b, 0x78, 0xfc, 0x67, 0x7d, 0x12};
	
	//а вот бля не факт
	int numberOfBlocks = ceil((double)len / 16); // Количество блоков для зашифрования
	
	int i, j;
	
	int w[Nb * (Nr + 1)]; // Расписание ключей
	keyExpansion(key, w); // Расширение ключа
	
	int cipherLength = getCipherLength(len);
	ciphertext = (uint8_t*)malloc(cipherLength); // Ну вот не совсем так, надо ещё функцию для дополнения
	
	for(i = 0; i < 1/*numberOfBlocks*/; ++i) // Пока разочек, а вообще по всем блокам должен пройти
	{
		encript_block(opentext, ciphertext, w);
		
		for(i = 0; i < 16; ++i)
			printf("%x", *(uint8_t *)opentext++);
	
			printf("\n%d\n", cipherLength);
			
		for(i = 0; i < 16; ++i)
			printf("%x", *(uint8_t *)ciphertext++);
			
		//ciphertext += 16;
	}
}






















