#include <stdio.h>
#include "GlobalGrid.h"
#include "crypto.h"
#include <iostream>
#include "cppext/cppext.h"
#include <map>
#include "database.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

using namespace System;
using namespace System::Net;
using namespace GlobalGrid;

class Session {
public:
  uint64_t key[4];
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
  ToHexString((unsigned char*)localguid.value,sizeof(localguid.value),guid_str);
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
  *((Guid*)(buffer+1)) = localguid;
  
  
  std::map<Guid,Session> sessions;
  auto bot = sessions.begin();
  
  auto sendHandshake = [&](const IPEndpoint& nextHop, const Guid& address){
    *((Guid*)(buffer+1)) = localguid;
    char guid_str[256];
    ToHexString((unsigned char*)address.value,sizeof(address.value),guid_str);
    void* key = DB_FindAuthority(guid_str);
    buffer[0] = 0;
    Session session;
    secure_random_bytes(session.key,sizeof(session.key));
    session.verified = true;
    sessions[address] = session;
    std::shared_ptr<Buffer> buffy = RSA_Encrypt(key,(unsigned char*)session.key,sizeof(session.key));
    memcpy(buffer+1+16,buffy->data,buffy->len);
    socket->Send(buffer,buffy->len+1+16,nextHop);
  };
  std::shared_ptr<UDPCallback> recvcb = F2UDPCB([&](const UDPCallback& cb){
    try {
      printf("received packet of length %i\n",(int)cb.outlen);
    BStream stream(buffer,cb.outlen);
    unsigned char opcode;
    stream.Read(opcode);
    Guid claimedThumbprint;
    stream.Read(claimedThumbprint.value);
    
   char guid_str[256];
    ToHexString((unsigned char*)claimedThumbprint.value,sizeof(claimedThumbprint.value),guid_str);
    
    printf("Received packet (opcode %i) from person claiming to be %s\n",(int)opcode,(char*)guid_str);
  *((Guid*)(buffer+1)) = localguid;
    
    switch(opcode) {
      case 0:
      {
	//Handshake request
	std::shared_ptr<Buffer> key = RSA_Decrypt(privkey,stream.ptr,stream.length);
	if(!key) {
	  //Unable to decrypt data.
	  printf("Error: Private key decrypt failure.");
	  return;
	}
	if(key->len<32) {
	  //Handshake -- bad key length
	  printf("Error. Bad key length.\n");
	  return;
	}
	//Buffers are guaranteed to be aligned on a 16-byte boundary.
	Session session;
	session.key[0] = ((uint64_t*)key->data)[0];
	session.key[1] = ((uint64_t*)key->data)[1];
	session.key[2] = ((uint64_t*)key->data)[2];
	session.key[3] = ((uint64_t*)key->data)[3];
	
	session.verified = false;
	secure_random_bytes(session.challenge,sizeof(session.challenge));
	sessions[claimedThumbprint] = session;
	printf("Got connection request from entity claiming to be %s\n",guid_str);
	void* auth = DB_FindAuthority(guid_str);
	if(!auth) {
	  //Send request for key
	  *buffer = 2;
	  socket->Send(buffer,1+16,cb.receivedFrom);
	}else {
	  //Send a challenge
	  std::shared_ptr<Buffer> buffy = RSA_Encrypt(auth,(unsigned char*)session.challenge,sizeof(session.challenge));
	  RSA_Free(auth);
	  uint16_t len = buffy->len;
	  *buffer = 1;
	  *(buffer+1+16) = 0;
	  memcpy(buffer+1+16+1,&len,sizeof(len));
	  memcpy(buffer+1+16+1+2,buffy->data,buffy->len);
	  size_t align = crypt_align(16,1+2+buffy->len);
	  aes_cbc_encrypt(session.key,(int64_t*)(buffer+1+16),align);
	  socket->Send(buffer,1+16+align,cb.receivedFrom);
	}
	
      }
	break;
      case 1:
      {
	//Encrypted packet
	if(sessions.find(claimedThumbprint) == sessions.end()) {
	  break;
	}
	Session session = sessions[claimedThumbprint];
	size_t enclen = stream.length;
	int64_t* encrypted = (int64_t*)(stream.Increment(enclen));
	aes_cbc_decrypt(session.key,encrypted,enclen);
	
	stream.ptr-=enclen;
	stream.length+=enclen;
	unsigned char opcode;
	stream.Read(opcode);
	printf("Encrypted substream, OPCODE %i\n",(int)opcode);
	switch(opcode) {
	  case 0:
	  {
	    //Challenge to duel
	    uint16_t len;
	    stream.Read(len);
	    std::shared_ptr<Buffer> buffy = RSA_Decrypt(privkey,stream.Increment(len),len);
	    if(!buffy) {
	      break;
	    }
	    printf("Challenge size = %i\n",(int)buffy->len);
	    if(buffy->len) {
	      //Challenge accepted!
	      size_t align = crypt_align(16,buffy->len+1);
	      buffer[1+16] = 1;
	      memcpy(buffer+1+16+1,buffy->data,buffy->len);
	      aes_cbc_encrypt(session.key,(int64_t*)(buffer+1+16),align);
	      socket->Send(buffer,align+1+16,cb.receivedFrom);
	    }
	  }
	    break;
	  case 1:
	  {
	    //Challenge response
	    Session session;
	    if(stream.length<sizeof(session.challenge)) {
	      printf("Illegal size\n");
	      return;
	    }
	    if(memcmp(session.challenge,stream.ptr,sizeof(session.challenge))) {
	      printf("Challenge mismatch\n");
	      break;
	    }
	    printf("Identity verified\n");
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
	memcpy(buffer+1+16,buffy->data,buffy->len);
	socket->Send(buffer,buffy->len+1+16,cb.receivedFrom);
	
      }
	break;
      case 3:
      {
	//Received public key
	void* key = RSA_Key(stream.ptr,stream.length);
	if(key) {
	  
	  RSA_thumbprint(key,guid_str);
	  Guid ian;
	  RSA_thumbprint(key,(unsigned char*)ian.value);
	  RSA_Free(key);
	  if(ian != claimedThumbprint) {
	    printf("Error. Possible (D)DoS attempt detected.\n");
	  }
	  void* auth = DB_FindAuthority(guid_str);
	  if(auth) {
	    RSA_Free(auth);
	  }else {
	    DB_Insert_Certificate(guid_str,stream.ptr,stream.length,false);
	  }
	  //Send connect request
	  
	  sendHandshake(cb.receivedFrom,ian);
	}
      }
	break;
	
	
    }
    }catch(const char* er) {
      
    }
    socket->Receive(buffer,buffsz,recvcb);
  });
  socket->Receive(buffer,buffsz,recvcb);
  
  if(argc>1) {
    //connect to remote endpoint via IP address
    *buffer = 2;
    IPEndpoint dest;
    dest.ip = argv[1];
    dest.port = atoi(argv[2]);
    socket->Send(buffer,1+16,dest);
  }
  
  int kernelfd = open("/dev/net/tun",O_RDWR);
  
  struct ifreq request;
  memset(&request,0,sizeof(request));
  request.ifr_flags = IFF_TAP;
  strcpy(request.ifr_name,"globalgrid0");
  if(ioctl(kernelfd,TUNSETIFF,(void*)&request)) {
    printf("Unable to start kernel-mode network driver. Please ensure that you're running this as root.\n");
    return -1;
  }
  
  unsigned char adapter_mac[6];
  ioctl(kernelfd,SIOCGIFHWADDR,(void*)&request);
  memcpy(adapter_mac,request.ifr_hwaddr.sa_data,6);
  ioctl(kernelfd,TUNGETIFF,&request);
  
  
  
  char adapter_hex[256];
  ToHexString(adapter_mac,6,adapter_hex);
  printf("Virtual network adapter %s\n",adapter_hex);
  
  std::shared_ptr<System::IO::Stream> netif = System::IO::FD2S(kernelfd);
  size_t iobuffsz = 1024*1024*5;
  unsigned char* iobuf = new unsigned char[iobuffsz];
  std::shared_ptr<System::IO::IOCallback> readcb = System::IO::IOCB([&](System::IO::IOCallback& data){
    BStream str(iobuf+4,data.outlen);
    struct ethhdr phy_header;
    str.Read(phy_header);
    ToHexString(phy_header.h_source,6,adapter_hex);
    if(memcmp(phy_header.h_source,adapter_mac,6)) {
      printf("WARNING: Dropped packet from %s. Promiscuous mode is not supported on this interface type.\n",adapter_hex);
      
    }
    netif->Read(iobuf,iobuffsz,readcb);
  });
  int sockfd = ::socket(AF_INET6, SOCK_DGRAM, 0);
  
  netif->Read(iobuf,iobuffsz,readcb);
  request.ifr_flags = IFF_UP;
  ioctl(sockfd,SIOCSIFFLAGS,&request);
  
  
  in6_addr i6addr;
  memcpy(&i6addr,localguid.value,16);
  struct in6_ifreq addrreq;
  addrreq.ifr6_addr = i6addr;
  addrreq.ifr6_ifindex = if_nametoindex("globalgrid0");
  addrreq.ifr6_prefixlen = 0; //0 bits for prefix length. GlobalGrid will attempt to route to ALL IPv6 addresses. This is the most secure setting; however, it may conflict with native IPv6 routing on
  //a local machine. Hopefully the kernel is smart enough to handle routing with two devices advertising the same address.....
  if(ioctl(sockfd,SIOCSIFADDR,&addrreq)) {
    printf("Failed to set virtual address on socket at index %i, errno = %i.\n",(int)request.ifr_ifindex,errno);
    return -1;
  }
  
  System::Enter();
}
