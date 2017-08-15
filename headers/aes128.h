#ifndef __AES_128_H__
#define __AES_128_H__

// �������������� ���������� � ������������ �� ���������� AES128
#define Nb 4 // ����� �������� � ������� ���������, 4 * Nb.
#define Nk 4 // ����� �������� � ������� �����, 4 * Nk.
#define Nr 10 // ���������� �������, ��� ������� �� �������� Nb � Nk.

#include "stdint.h"

int keyExpansion(uint8_t key[4 * Nk], int w[Nb * (Nr + 1)]);

int encrypt_block(uint8_t input[4 * Nb], uint8_t output[4 * Nb], int w[Nb * (Nr + 1)]);

int decrypt_block(uint8_t input[4 * Nb], uint8_t output[4 * Nb], int w[Nb * (Nr + 1)]);

uint32_t encryptData(void *opentext, uint32_t len);

uint32_t decryptData(void *ciphertext, uint32_t cipherLength);

#endif //__AES_128_H__
