#include <stdio.h>
#include "GlobalGrid.h"
#include "crypto.h"
#include <iostream>
#include "cppext/cppext.h"
#include <uuid/uuid.h>
#include <map>
#include "database.h"

using namespace System;
using namespace System::Net;
using namespace GlobalGrid;

class Session {
public:
  uint64_t key[2];
  uint64_t challenge[2];
  bool verified;
  
};

int main(int argc, char** argv)
{
  
  //TODO: New hole punching method: UDP/ICMP hole punching (ICMP packets are usually routed through NATs)
  
  
  std::cout<<"GlobalGrid Protocol Client"<<std::endl;
  std::cout<<"Reference Implementation. Not intended for production use."<<std::endl;
  
  void* privkey = 0;
  void* thisptr;
  bool(*cb)(void* thisptr, unsigned char* mander, size_t sz);
  thisptr = System::ABI::C([&](unsigned char* mander,size_t sz){
    privkey = RSA_Key(mander,sz);
    return false;
  },cb);
  DB_EnumPrivateKeys(thisptr,cb);
  char guid_str[256];
  if(privkey == 0) {
    
  std::cout<<"Generating key...."<<std::endl;
   privkey = RSA_GenKey(8192);
   std::cout<<"Keygen complete"<<std::endl;
   std::shared_ptr<Buffer> itbytes = RSA_Export(privkey,true);
   RSA_thumbprint(privkey,guid_str);
   DB_Insert_Certificate(guid_str,(unsigned char*)itbytes->data,itbytes->len,true);
  }
  Guid localguid;
  RSA_thumbprint(privkey,(unsigned char*)localguid.value);
  uuid_unparse((unsigned char*)localguid.value,guid_str);
  std::cout<<"Your ID is "<<guid_str<<std::endl;
  
  std::shared_ptr<UDPSocket> socket = CreateUDPSocket();
  IPEndpoint localEP;
  socket->GetLocalEndpoint(localEP);
  std::cout<<"Server running on port "<<localEP.port<<std::endl;
  size_t buffsz = 1024*1024*5;
  unsigned char* buff_alloc = (unsigned char*)aligned_alloc(16,16+buffsz);
  unsigned char* buffer = buff_alloc+15;
  if(((size_t)buffer+1) % 16) {
    printf("Alignment fault %i\n",(int)(((size_t)buffer+1) % 16));
    abort();
  }
  std::map<Guid,Session> sessions;
  auto bot = sessions.begin();
  
  auto sendHandshake = [&](const IPEndpoint& nextHop, const Guid& address){
    char guid_str[256];
    uuid_unparse((unsigned char*)address.value,guid_str);
    void* key = DB_FindAuthority(guid_str);
    buffer[0] = 0;
    Session session;
    secure_random_bytes(session.key,sizeof(session.key));
    session.verified = true;
    sessions[address] = session;
    std::shared_ptr<Buffer> buffy = RSA_Encrypt(key,(unsigned char*)session.key,sizeof(session.key));
    socket->Send(buffy->data,buffy->len,nextHop);
  };
  
  socket->Receive(buffer,buffsz,F2UDPCB([&](const UDPCallback& cb){
    try {
    BStream stream(buffer,cb.outlen);
    Guid claimedThumbprint;
    stream.Read(claimedThumbprint.value);
    
   char guid_str[256];
    uuid_unparse((unsigned char*)claimedThumbprint.value,guid_str);
    unsigned char opcode;
    stream.Read(opcode);
    switch(opcode) {
      case 0:
      {
	//Handshake request
	std::shared_ptr<Buffer> key = RSA_Decrypt(privkey,stream.ptr,stream.length);
	if(!key) {
	  //Unable to decrypt data.
	  return;
	}
	if(key->len<32) {
	  //Handshake -- bad key length
	  return;
	}
	//Buffers are guaranteed to be aligned on a 16-byte boundary.
	Session session;
	session.key[0] = ((uint64_t*)key->data)[0];
	session.key[1] = ((uint64_t*)key->data)[1];
	session.verified = false;
	secure_random_bytes(session.challenge,sizeof(session.challenge));
	sessions[claimedThumbprint] = session;
	printf("Got connection request from entity claiming to be %s\n",guid_str);
	void* auth = DB_FindAuthority(guid_str);
	if(!auth) {
	  //Send request for key
	  socket->Send(buffer,1,cb.receivedFrom);
	}else {
	  std::shared_ptr<Buffer> buffy = RSA_Encrypt(auth,(unsigned char*)session.challenge,sizeof(session.challenge));
	  RSA_Free(auth);
	  uint16_t len = buffy->len;
	  memcpy(buffer+2,&len,sizeof(len));
	  memcpy(buffer+2+2,buffy->data,buffy->len);
	  size_t align = crypt_align(16,1+2+buffy->len);
	  aes_cbc_encrypt(session.key,(int64_t*)buffer+1,align);
	  socket->Send(session.key,align+1,cb.receivedFrom);
	}
	
      }
	break;
      case 1:
      {
	//Encrypted packet
	if(sessions.find(claimedThumbprint) == sessions.end()) {
	  return;
	}
	Session session = sessions[claimedThumbprint];
	aes_cbc_decrypt(session.key,buffer+1,cb.outlen-1);
	unsigned char opcode;
	stream.Increment(1);
	stream.Read(opcode);
	switch(opcode) {
	  case 0:
	  {
	    //Challenge to duel
	    uint16_t len;
	    stream.Read(len);
	    std::shared_ptr<Buffer> buffy = RSA_Decrypt(privkey,stream.Increment(len),len);
	    if(!buffy) {
	      return;
	    }
	    if(buffy->len) {
	      //Challenge accepted!
	      size_t align = crypt_align(16,buffy->len);
	      memcpy(buffer+2,buffy->data,buffy->len);
	      buffer[1] = 1;
	      aes_cbc_encrypt(session.key,(int64_t*)(buffer+1),align);
	      socket->Send(buffer,align+2,cb.receivedFrom);
	    }
	  }
	    break;
	}
	
      }
	break;
      case 2:
      {
	//Request for public key
	std::shared_ptr<Buffer> buffy = RSA_Export(privkey,false);
	buffer[0] = 3;
	memcpy(buffer+1,buffy->data,buffy->len);
	socket->Send(buffer,buffy->len+1,cb.receivedFrom);
	
      }
	break;
      case 3:
      {
	//Received public key
	void* key = RSA_Key(buffer,cb.outlen);
	if(key) {
	  
	  RSA_thumbprint(key,guid_str);
	  
	  void* auth = DB_FindAuthority(guid_str);
	  if(auth) {
	    RSA_Free(auth);
	  }else {
	    DB_Insert_Certificate(guid_str,buffer,cb.outlen,false);
	  }
	  //Send connect request
	  Guid ian;
	  RSA_thumbprint(key,(unsigned char*)ian.value);
	  sendHandshake(cb.receivedFrom,ian);
	}
      }
	break;
	
	
    }
    }catch(const char* er) {
      
    }
  }));
  System::Enter();
}
