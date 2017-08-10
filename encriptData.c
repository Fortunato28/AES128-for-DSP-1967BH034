#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "aes128.h"

#define LENGTH 80 // ����� ��������� ������

void encriptData(void *opentext, int len, void *ciphertext); // ��, ��� ��� � ������ ����������
 
void main( void )
{
	uint8_t data[] = {0xfa, 0x8d, 0x03, 0x5d, 0xde, 0x0e, 0x32, 0xfa, 0xab, 0x7c, 0xb7, 0xbf, 0xd9, 0xa0, 0x7a, 0xaf, 0x27, 0x92, 0x80, 0x67, 0x01, 0x73, 0x26, 0x25, 0x40, 0x57, 0x62, 0x86, 0x21, 0x52, 0x49, 0x24, 0x04, 0x26, 0x73, 0x28, 0x32, 0x17, 0x65, 0x10, 0x27, 0x92, 0x45, 0x92, 0x50, 0x92, 0x76, 0x83, 0x72, 0x65, 0x40, 0x27, 0x96, 0x21, 0x67, 0x62, 0x17, 0x96, 0x52, 0x49, 0x25, 0x78, 0x76, 0x65, 0x42, 0x04, 0x62, 0x97, 0x84, 0x94, 0x23, 0x49, 0x09, 0x27};
	int len = LENGTH;
	uint8_t *ciphertext;
	
	
	encriptData(data, len, ciphertext);
	
		while(1);
}


/**
  * @brief  ��������� ����� ����������� ��� ��������� ������ ��� ����, � ������������ � PKCS7
  * @param  ����� ��������� ������ len
  * @retval ����� �����������
  */
int getCipherLength(int len)
{
	int cipherLength = len;
	int shortageUpToMultiplicity = 16 - (len % 16); // ���������� �� ��������� 128
	
	if(len % 16 != 0) // ��������� 128 �����
	{
		cipherLength += shortageUpToMultiplicity; // ����������� ����� ���������� �����
	}
	else
	{
		cipherLength += 16; // ��������� ����� ����, ���� ����� ��������� ������ 128 �����
	}
		return cipherLength;
}


/**
  * @brief  ���������� ����� ������ ������������ �����
  * @param  ��������� �� ������ ��������� ������ opentext, ����� ��������� ������ len, 
  					��������� �� ������ ������� ��� ������ ����������� ciphertext, ���� ���������� key
  * @retval ���� ������ � �������������� �������
  */
void encriptData(void *opentext, int len, void *ciphertext) // ����� ����� ���������, ��� ������ �� ������?
{
	uint8_t key[4 * Nk] = {0x66, 0xa3, 0x6c, 0x8b, 0x8c, 0x54, 0x92, 0x52, 0x7c, 0xd7, 0x6b, 0x78, 0xfc, 0x67, 0x7d, 0x12};
	
	//� ��� ��� �� ����
	int numberOfBlocks = ceil((double)len / 16); // ���������� ������ ��� ������������
	
	int i, j;
	
	int w[Nb * (Nr + 1)]; // ���������� ������
	keyExpansion(key, w); // ���������� �����
	
	int cipherLength = getCipherLength(len);
	ciphertext = (uint8_t*)malloc(cipherLength); // �� ��� �� ������ ���, ���� ��� ������� ��� ����������
	
	for(i = 0; i < 1/*numberOfBlocks*/; ++i) // ���� �������, � ������ �� ���� ������ ������ ������
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






















