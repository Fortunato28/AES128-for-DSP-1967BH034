#include <stdio.h>
#include <stdlib.h>
#include "aes128.h"

#define OPENLENGTH 74 // ����� ��������� ������
#define CIPHERLENGTH 80 // ����� ����������
//74


// ���� ����������
uint8_t key[4 * Nk] = {0x66, 0xa3, 0x6c, 0x8b, 0x8c, 0x54, 0x92, 0x52, 0x7c, 0xd7, 0x6b, 0x78, 0xfc, 0x67, 0x7d, 0x12};

/**
  * @brief  ������������ ������� ������
  * @param  -, ������ ����� ����� ��������� �� ������� ������ � �� �����
  * @retval -
  */
void main( void )
{

	 	uint8_t data[] = {0xfa, 0x8d, 0x03, 0x5d, 0xde, 0x0e, 0x32, 0xfa, 0xab, 0x7c, 0xb7, 0xbf, 0xd9, 0xa0, 0x7a, 0xaf, 0x13, 0x3c, 0x86, 0xcd, 0xc6, 0xf6, 0xe6, 0x41, 0x4a, 0x12, 0xf8, 0x7c, 0x26, 0x61, 0xfc, 0x38, 0xbe, 0xd7, 0x71, 0x88, 0x32, 0xaf, 0x6c, 0xbe, 0x57, 0x89, 0x71, 0x60, 0x61, 0x48, 0x69, 0x60, 0xaa, 0x3e, 0xb6, 0xf8, 0xe6, 0x5f, 0xd1, 0x1b, 0x80, 0x57, 0xfc, 0x92, 0x6f, 0xbb, 0xb8, 0xa8, 0x71, 0x32, 0x43, 0x5a, 0x15, 0xb1, 0x56, 0x6f, 0xda, 0xc9/**/ };
 	int j;
	
	
	// ���������� ���� ��� ������������
	uint8_t *ciphertext;
	int len = OPENLENGTH;
	int cipherLength = getCipherLength(len); // ����� �����������
	ciphertext = encriptData(data, len);
	
	for(j = 0; j < cipherLength; ++j)
			printf("%x", *(ciphertext + j));
			
	// ����������� ���� ��� �������������
	uint8_t *opentext;
	int lengthOfCipher = CIPHERLENGTH;
	opentext = decriptData(ciphertext, lengthOfCipher);
	int opentextLength = getOpentextLength(opentext, lengthOfCipher); // ����� �������� ��������� ��������� ������
	
	printf("\n Length of opentext = %d\n", opentextLength);
	for(j = 0; j < opentextLength; ++j)
			printf("%x", *(opentext + j));
	
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
  * @param  ��������� �� ������ ��������� ������ opentext, ����� ��������� ������ len
  * @retval ��������� �� ���� ������ � �������������� �������
  */
int encriptData(void *opentext, int len) // ����� ����� ���������, ��� ������ �� ������?
{
	int w[Nb * (Nr + 1)]; // ���������� ������
	keyExpansion(key, w); // ���������� �����
	
	uint8_t *ciphertext;
	int i, j;
	uint8_t buff[4 * Nb]; // ����� ��� ����� �������� ������
	uint8_t blockShortageUpToMultiplicity = 16 - (len % 16); // ���������� ���������� ����� �� ��������� 128
	
	int cipherLength   = getCipherLength(len); // ��������� ����� �����������
	int numberOfBlocks = cipherLength / 16;    // ���������� ������ �����������
	ciphertext         = malloc(cipherLength); // ���������� ������, ���������� ��� ���� �����������, ������ 128 �����
	

	// ��� �� ������
	for(i = 0; i < numberOfBlocks; ++i) // ������� ������ ���� ��������
	{
		// ��� ���������� ����� ������ ������������ ����������
		if(i == numberOfBlocks - 1)
		{
			if(blockShortageUpToMultiplicity == 16) // ����� ����� ������ 128, �� ��������� ��� ����� ������
			{
				memset(buff, 0x10, 16); // ��������� ��������� ���� 				
			}
			else // ����� ������ �� ������ 128, ��������� ������� ���������� ����� �� ���������
			{
				for(j = 0; j < len % 16; ++j)
				{
					memcpy(buff, opentext, len % 16);
				}
				memset(buff + (len % 16), blockShortageUpToMultiplicity, blockShortageUpToMultiplicity);
			}
		}
		
		
		// �������
		if(i != numberOfBlocks - 1)
		{
			encript_block(opentext, ciphertext, w);
		}
		else
		{
			encript_block(buff, ciphertext, w); // ��������� ���� �������� �������� ��-�� ���������
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
			
		opentext += 16; // �������� ���������� ��� ������ �� ��������� ������ ������
		ciphertext += 16;
	}
	return ciphertext - cipherLength;
}


/**
  * @brief  ��������� ����� �������� ������ � ������� �����������
  * @param  ��������� �� ������� ������������� ������ � �� �����
  * @retval ����� �������� ������ � ������� �����������
  */
int getOpentextLength(uint8_t *opentext, int lengthOfCipher)
{
	uint8_t buff[4 * Nb]; // ��� �������� �� ���� ��������� ����������� ����
	memset(buff, 0x10, 16); // ��� �������� �� ���� ��������� ����������� ����
	uint8_t lastBlock[4 * Nb]; // ����� ��� ���������� ����� ������
	memcpy(lastBlock, opentext + lengthOfCipher - 16, 16); // ��������� ����� ��������� ������
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
  * @brief  ������������� ������� ������
  * @param  -, ������ ����� ����� ��������� �� ������� ������������� ������ � �� �����
  * @retval -
  */
int decriptData(void *ciphertext, int lengthOfCipher)
{
	int w[Nb * (Nr + 1)]; // ���������� ������
	keyExpansion(key, w); // ���������� �����
	
	uint8_t *opentext;
	opentext = malloc(lengthOfCipher); // ���������� ������ ��� ���� ��������� ������ ������ 128 �����
	
	int i, j;
	uint8_t buff[4 * Nb]; // ����� ��� ����� �������� ������
	int numberOfBlocks = lengthOfCipher / 16; // ���������� ������ �����������
	//uint8_t blockShortageUpToMultiplicity = 16 - (len % 16); // ���������� ���������� ����� �� ��������� 128
	
	
	// ��������������
	for(i = 0; i < numberOfBlocks; ++i)
	{
			decript_block(ciphertext, opentext, w);
			
			// �������� ���������� ��� ������ �� ��������� ������ ������
			ciphertext += 16;
			opentext += 16;
	} 
	
	return opentext - lengthOfCipher;
}





















