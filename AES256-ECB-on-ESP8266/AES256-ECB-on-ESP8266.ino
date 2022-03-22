#include <my-aes.h>
#include <stdio.h>
#include <memory.h>

/*
 * my-aes library needs to be installed: place in Documents\Arduino\libearies\my-aes path.
 * Source files in AES128-ECB-on-ESP8266, from current Github repository.
 * This code is an adaptation of Brad Conte "aes_test.c" code.
 */

void setup() {

  Serial.begin(9600);
  pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
  digitalWrite(LED_BUILTIN, LOW);   // Turn the LED on (Note that LOW is the voltage level
  char serialMonitor_buffer[100];
  sprintf(serialMonitor_buffer, "AES Tests: %s\n", aes_test() ? "SUCCEEDED" : "FAILED");
  Serial.print(serialMonitor_buffer);
  digitalWrite(LED_BUILTIN, HIGH);  // Turn the LED off by making the voltage HIGH
  delay(2000);

}

void print_hex(BYTE str[], int len)
{
  int idx;

  for(idx = 0; idx < len; idx++)
    Serial.print(str[idx], HEX);
}

int aes_ecb_test()
{
  char serialMonitor_buffer_local[100];
  
  WORD key_schedule[60], idx;
  BYTE enc_buf[128];

  // 16 bytes messages
  BYTE plaintext[2][16] = {
    {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
    {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
  };
  // 16 bytes cyphered with the key 
  BYTE ciphertext[2][16] = {
    {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
    {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
  };
  // Key 256-bit long (64 bytes)
  BYTE key[1][32] = {
    {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
  };
  int pass = 1;

  // Raw ECB mode.
  sprintf(serialMonitor_buffer_local, "* ECB mode:\n");
  Serial.print(serialMonitor_buffer_local);
  
  aes_key_setup(key[0], key_schedule, 256);
  
  sprintf(serialMonitor_buffer_local, "Key          : ");
  Serial.print(serialMonitor_buffer_local);
  
  print_hex(key[0], 32);

  for(idx = 0; idx < 2; idx++) {
    aes_en_crypt(plaintext[idx], enc_buf, key_schedule, 256);
    
    sprintf(serialMonitor_buffer_local, "\nPlaintext    : ");
    Serial.print(serialMonitor_buffer_local);
    
    print_hex(plaintext[idx], 16);
    
    sprintf(serialMonitor_buffer_local, "\n-encrypted to: ");
    Serial.print(serialMonitor_buffer_local);
    
    print_hex(enc_buf, 16);
    
    pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);

    aes_de_crypt(ciphertext[idx], enc_buf, key_schedule, 256);
    
    sprintf(serialMonitor_buffer_local, "\nCiphertext   : ");
    Serial.print(serialMonitor_buffer_local);
    
    print_hex(ciphertext[idx], 16);
    
    sprintf(serialMonitor_buffer_local, "\n-decrypted to: ");
    Serial.print(serialMonitor_buffer_local);
    
    print_hex(enc_buf, 16);
    
    pass = pass && !memcmp(enc_buf, plaintext[idx], 16);

    sprintf(serialMonitor_buffer_local, "\n\n");
    Serial.print(serialMonitor_buffer_local);
  }

  return(pass);
}

int aes_test()
{
  int pass = 1;

  pass = pass && aes_ecb_test();
//  pass = pass && aes_cbc_test();
//  pass = pass && aes_ctr_test();
//  pass = pass && aes_ccm_test();

  return(pass);
}
