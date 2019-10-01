/*
This code is a modified version of avaiölable example in contiki-3.0
contiki-3.0/examples/llsec/ccm-star-tests/encryption/test.c
*/

#include "contiki.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "net/llsec/llsec802154.h"
#include "lib/ccm-star.h"
#include "net/llsec/ccm-star-packetbuf.h"
#include "net/mac/frame802154.h"
#include <stdio.h>
#include <string.h>
#define DATA_SIZE 16
uint8_t nonce[8] = { 0xAC , 0xDE , 0x48 , 0x00 ,
                     0x00 , 0x00 , 0x00 , 0x01 };
uint8_t * ret_data;
static void
init_aes()
{

 uint8_t key[16] = { 0xC0 , 0xC1 , 0xC2 , 0xC3 ,
                     0xC4 , 0xC5 , 0xC6 , 0xC7 ,
                     0xC8 , 0xC9 , 0xCA , 0xCB ,
                     0xCC , 0xCD , 0xCE , 0xCF };

 CCM_STAR.set_key(key);
}
static void
crypt_aes(uint8_t * data)
{
 	uint8_t mic[LLSEC802154_MIC_LENGTH];
 	frame802154_frame_counter_t counter;

 	packetbuf_clear();
	packetbuf_set_datalen(DATA_SIZE);
        memcpy(packetbuf_hdrptr(), data, DATA_SIZE);
 	counter.u32 = 5;
 	packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1, counter.u16[0]);
 	packetbuf_set_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3, counter.u16[1]);
 	packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, LLSEC802154_SECURITY_LEVEL);
 	packetbuf_hdrreduce(0);
	ccm_star_mic_packetbuf(nonce, mic, LLSEC802154_MIC_LENGTH);

 	ccm_star_ctr_packetbuf(nonce);

}
static void
encrypt_aes(uint8_t * data)
{
	crypt_aes(data);

}
static void
decrypt_aes(uint8_t *data)
{
	crypt_aes(data);
}
