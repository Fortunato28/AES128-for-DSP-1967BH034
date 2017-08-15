/*****************************************************************************
  * @file    E:\Projetcs\C\encryptData
  * @author  Sapunov A.
  * @version -
  * @date    07.08.2017
  * @brief   ������������ � ������������ ������ ������������ ������ AES128.
 
  *****************************************************************************/
  
#include <stdio.h>
#include <stdlib.h>
#include "aes128.h"

#define ENCRYPTIONMODE 0   // ����� ���������� EBC (����������� ������� �����), ����� CBC
#define OPENLENGTH     74  // ����� ��������� ������ (������, ������� ���������� �����������)
#define CIPHERLENGTH   80  // ����� ����������� (������������� ������)
//74


int getIV( void );

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
	
	
	// ���������� ���������� ��� ������������
	uint8_t  *ciphertext;
	uint32_t cipherLength;
	
	ciphertext   = encryptData(data, OPENLENGTH); // ��������� ������ ������ ������� ������������� ������
	cipherLength = getCipherLength(OPENLENGTH);   // ����� �����������
	
	for(j = 0; j < cipherLength; ++j)
			printf("%x", *(ciphertext + j));
					
			
	// ����������� ���������� ��� �������������
	uint8_t  *opentext;
	uint32_t opentextLength;
	
	opentext       = decryptData(ciphertext, CIPHERLENGTH);     // ��������� ������ ������������� ������
	opentextLength = getOpentextLength(opentext, CIPHERLENGTH); // ��������� ����� �������� ������ ��������� ������
	
	printf("\n");
	for(j = 0; j < opentextLength; ++j)
			printf("%x", *(opentext + j));
									
		while(1);
}




/**
  * @brief  ��������� ����� ����������� ��� ��������� ������ ��� ����, � ������������ � PKCS7
  * @param  len          - ����� ��������� ������
  * @retval cipherLength - ����� �����������
  */
uint32_t getCipherLength(uint32_t len)
{
	uint32_t cipherLength        			= len;
	uint8_t  shortageUpToMultiplicity = (Nb * 4) - (len % (Nb * 4)); // ���������� �� ��������� 128
	
	if(len % (Nb * 4) != 0) 																	       // ��������� 128 �����
	{
		cipherLength += shortageUpToMultiplicity; 								     // ����������� ����� ���������� �����
	}
	else
	{
		cipherLength += (Nb * 4); 																     // ��������� ����� ����
	}
		return cipherLength;
}

/**
  * @brief  ���������� ����� ������ ������������ �����
  * @param  opentext -  ��������� �� ������ ��������� ������
  * @param  len      -  ����� ��������� ������   
  * @retval ����� ������� ����� ������ � �������������� �������
  */
uint32_t encryptData(void *opentext, uint32_t len) // ����� ����� ���������, ��� ������ �� ������?
{	
	
	int w[Nb * (Nr + 1)]; // ���������� ������
	keyExpansion(key, w); // ���������� �����
	
	uint32_t cipherLength;
	uint32_t numberOfBlocks;
	uint8_t  *ciphertext;
	uint8_t  buff[4 * Nb];                                    	 // ����� ��� ����� �������� ������
	uint8_t  blockShortageUpToMultiplicity;
	int      i, j;
	
	cipherLength   = getCipherLength(len);    // ��������� ����� �����������
	numberOfBlocks = cipherLength / (Nb * 4); // ���������� ������ �����������
	ciphertext     = malloc(cipherLength);    // ���������� ������, ���������� ��� ���� �����������, ������ 128 �����
	blockShortageUpToMultiplicity = (Nb * 4) - (len % (Nb * 4)); // ���������� ���������� ����� �� ��������� 128
	
	
	// ��� �� ������
	for(i = 0; i < numberOfBlocks; ++i) // ������� ������ ���� ��������
	{
		// ��� ���������� ����� ������ ������������ ����������
		if(i == numberOfBlocks - 1)
		{
			if(blockShortageUpToMultiplicity == Nb * 4) // ����� ����� ������ 128, �� ��������� ��� ����� ������
			{
				memset(buff, 0x10, 16);                   // ��������� ��������� ���� 				
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
			encrypt_block(opentext, ciphertext, w);
		}
		else
		{
			encrypt_block(buff, ciphertext, w); // ��������� ���� �������� �������� ��-�� ����������
		}
			
		// �������� ���������� �� ���� ��� ������ �� ��������� ������ ������
		opentext   += (Nb * 4);
		ciphertext += (Nb * 4);
	}
  
	return ciphertext - cipherLength;
}


/**
  * @brief  ��������� ����� �������� ������ � ������� �����������
  * @param  opentext - ��������� �� ������� �������������� ������
  * @param  lengthOfCipher - ����� ������� �������������� ������
  * @retval ����� �������� ������ � ������� �����������
  */
uint32_t getOpentextLength(uint8_t *opentext, uint32_t lengthOfCipher)
{
	uint8_t buff[4 * Nb];                                      // ��� �������� �� ���� ��������� ����������� ����
	memset(buff, 0x10, Nb * 4); 
	uint8_t lastBlock[4 * Nb];                                 // ����� ��� ���������� ����� ������
	memcpy(lastBlock, opentext + lengthOfCipher - Nb * 4, (Nb * 4)); // ��������� ����� ��������� ������
	int i, j;
	
	// ����������� �� ���� ����������
		if(!memcmp(lastBlock, buff, (Nb * 4)))
			return lengthOfCipher - (Nb * 4);
		else
			return  lengthOfCipher - lastBlock[15];
}


/*
  * @brief  ������������� ������� ������
  * @param  ciphertext - ��������� �� ������� ������������� ������
  * @param  lengthOfCipher - ����� ������������� ������
  * @retval ����� ������ ����� �������������� ������
  */
uint32_t decryptData(void *ciphertext, uint32_t lengthOfCipher)
{	
	int w[Nb * (Nr + 1)];                       // ���������� ������
	keyExpansion(key, w);                       // ���������� �����
	
	uint32_t numberOfBlocks;                    // ���������� ������ �����������
	uint8_t *opentext;
	uint8_t buff[4 * Nb];                       // ����� ��� ����� �������� ������
	int i, j;  
	
	opentext = malloc(lengthOfCipher);          // ���������� ������ ��� ���� ��������� ������ ������ 128 �����
	numberOfBlocks = lengthOfCipher / (Nb * 4); // ���������� ������ �����������
	
	// ��������������
	for(i = 0; i < numberOfBlocks; ++i)
	{
			decrypt_block(ciphertext, opentext, w);
			
			// �������� ���������� ��� ������ �� ��������� ������ ������
			opentext   += (Nb * 4);
			ciphertext += (Nb * 4);
	} 	
	return opentext - lengthOfCipher;
}
