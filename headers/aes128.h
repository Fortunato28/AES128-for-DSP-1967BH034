#ifndef __AES_128_H__
#define __AES_128_H__

// �������������� ���������� � ������������ �� ���������� AES128
#define Nb 4 // ����� �������� � ������� ���������, 4 * Nb.
#define Nk 4 // ����� �������� � ������� �����, 4 * Nk.
#define Nr 10 // ���������� �������, ��� ������� �� �������� Nb � Nk.

#include "stdint.h"

int keyExpansion(uint8_t key[4 * Nk], int w[Nb * (Nr + 1)]);

int encript_block(uint8_t input[4 * Nb], uint8_t output[4 * Nb], int w[Nb * (Nr + 1)]);

int decript_block(uint8_t input[4 * Nb], uint8_t output[4 * Nb], int w[Nb * (Nr + 1)]);

#endif //__AES_128_H__
