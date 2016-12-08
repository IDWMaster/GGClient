/*

 This file is part of the GlobalGrid Protocol Suite.

    GlobalGrid is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GlobalGrid is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GlobalGrid.  If not, see <http://www.gnu.org/licenses/>.
 * */

#include "crypto.h"
#include "cppext/cppext.h"
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <memory>

namespace GlobalGrid {

void secure_random_bytes(void* output, size_t outlen)
{
  while(RAND_bytes((unsigned char*)output,outlen) == 0) {}
}


void aes_encrypt(const void* key, void* data)
{
  AES_KEY mkey;
  
  AES_set_encrypt_key((unsigned char*)key,256,&mkey);
  AES_encrypt((unsigned char*)data,(unsigned char*)data,&mkey);
  
}
static BIGNUM* ReadBig(System::BStream& str) {
  uint16_t len;
  str.Read(len);
  return BN_bin2bn(str.Increment(len),len,0);
}
static void WriteBig(System::BStream& str, const BIGNUM* number) {
  uint16_t len = BN_num_bytes(number);
  str.Write(len);
  BN_bn2bin(number,str.ptr);
  str.Increment(len);
}

void* RSA_Key(unsigned char* data, size_t len)
{
  System::BStream str(data,len);
  try {
  RSA* msa = RSA_new();
  msa->n = ReadBig(str); //Public modulus
  msa->e = ReadBig(str); //Public exponent
  
  if(str.length) {
    msa->d = ReadBig(str); //Private exponent
    msa->p = ReadBig(str); //Secret prime factor
    msa->q = ReadBig(str); //Secret prime factor
    msa->dmp1 = ReadBig(str); //d mod (p-1)
    msa->dmq1 = ReadBig(str); //d mod (q-1)
    msa->iqmp = ReadBig(str); //q^-1 mod p
    
  }
  return msa;
  }catch(const char* err) {
    return 0;
  }
}

std::shared_ptr<Buffer> RSA_Export(void* key, bool includePrivate)
{
  RSA* msa = (RSA*)key;
  if(includePrivate) {
    size_t len = 2+BN_num_bytes(msa->n)+2+BN_num_bytes(msa->e)+2+BN_num_bytes(msa->d)+2+BN_num_bytes(msa->p)+2+BN_num_bytes(msa->q)+2+BN_num_bytes(msa->dmp1)+2+BN_num_bytes(msa->dmq1)+2+BN_num_bytes(msa->iqmp);
    std::shared_ptr<GlobalGrid::Buffer> retval = std::make_shared<Buffer>(len);
    
    System::BStream str(retval->data,len);
    WriteBig(str,msa->n);
    WriteBig(str,msa->e);
    WriteBig(str,msa->d);
    WriteBig(str,msa->p);
    WriteBig(str,msa->q);
    WriteBig(str,msa->dmp1);
    WriteBig(str,msa->dmq1);
    WriteBig(str,msa->iqmp);
    return retval;
  }else {
    size_t len = 2+BN_num_bytes(msa->n)+2+BN_num_bytes(msa->e);
    std::shared_ptr<GlobalGrid::Buffer> retval = std::make_shared<Buffer>(len);
    System::BStream str(retval->data,len);
    WriteBig(str,msa->n);
    WriteBig(str,msa->e);
    return retval;
  }
}


void hash_generate(const unsigned char* data, size_t len, char* output)
{
  //Poor unsigned Charmander....
  unsigned char mander[64];
  SHA512(data,len,mander);
  const char* hex = "0123456789ABCDEF";
  size_t c = 0;
  for(size_t i = 0;i<16;i++) {
    output[c] = hex[mander[i] >> 4]; //Get lower 4 bits
    c++; //This is how C++ was invented.
    output[c] = hex[((mander[i] << 4) & 0xff) >> 4];//Get upper 4 bits
    c++; //This is how C++ was invented.
  }
  
}

void hash_generate(const unsigned char* data, size_t len, unsigned char* output)
{

  //Poor unsigned Charmander....
  unsigned char mander[64];
  SHA512(data,len,mander);
  memcpy(output,mander,16);
}



void* RSA_GenKey(size_t bits)
{
 // BIGNUM* e = BN_new();
  //  BN_set_word(e, 65537);
  RSA* msa = RSA_generate_key(bits,65537,0,0);
  //BN_free(e);
  return msa;
}




void RSA_Free(void* key)
{
  RSA_free((RSA*)key);
}

std::shared_ptr<Buffer> RSA_Encrypt(void* _key, unsigned char* input, size_t inlen)
{
  RSA* key = (RSA*)_key;
  std::shared_ptr<Buffer> outbuf = std::make_shared<Buffer>(RSA_size(key));
  RSA_public_encrypt(inlen,input,outbuf->data,key,RSA_PKCS1_PADDING);
  return outbuf;
}

std::shared_ptr<GlobalGrid::Buffer> RSA_Decrypt(void* _key, unsigned char* input, size_t inlen)
{
  RSA* key = (RSA*)_key;
  size_t outlen = RSA_size(key);
  unsigned char* output = (unsigned char*)malloc(outlen);
  int sz = RSA_private_decrypt(inlen,input,output,key,RSA_PKCS1_PADDING);
  if(sz<=0) {
    free(output);
    return 0;
  }
  std::shared_ptr<GlobalGrid::Buffer> outbuf = std::make_shared<GlobalGrid::Buffer>(sz);
  memcpy(outbuf->data,output,sz);
  free(output);
  return outbuf;
}






void aes_decrypt(const void* key, void* data)
{
  
  AES_KEY mkey;
  AES_set_decrypt_key((unsigned char*)key,256,&mkey);
  AES_decrypt((unsigned char*)data,(unsigned char*)data,&mkey);
}


}