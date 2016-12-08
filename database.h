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

#ifndef FREESPEECH_DATABASE
#define FREESPEECH_DATABASE

#include <memory>
#include <string.h>
#include "cppext/cppext.h"
#include "GlobalGrid.h"
#include "crypto.h"


namespace GlobalGrid {



class NamedObject {
public:
  char* id; //Blob ID == hash of contents
  char* name; //Blob name == Friendly name
  char* parent; //Parent Blob ID
  char* owner; //Owner of BLOB
  unsigned char* blob; //Raw BLOB as transmitted over network
  //Blob length
  size_t bloblen;
  
};




/**
 * @summary Serializes a NamedObject to a byte array. The resultant array can be freed with free();
 * */
static inline void* NamedObject_Serialize(const NamedObject& obj, size_t& outsz) {
  outsz = strlen(obj.id)+1+strlen(obj.name)+1+strlen(obj.parent)+1+strlen(obj.owner)+1+obj.bloblen;
  unsigned char* bytes = (unsigned char*)malloc(outsz);
  System::BStream bstr(bytes,outsz);
  bstr.Write(obj.id);
  bstr.Write(obj.name);
  bstr.Write(obj.parent);
  bstr.Write(obj.owner);
  memcpy(bstr.ptr,obj.blob,obj.bloblen);
  return bytes;
}
/**
 * @summary Deserializes a NamedObject from a byte array of size len.
 * */
static inline void NamedObject_Deserialize(const void* bytes, size_t len, NamedObject& obj) {
  System::BStream str((unsigned char*)bytes,len);
  
  obj.id = str.ReadString();
  obj.name = str.ReadString();
  obj.parent = str.ReadString();
  obj.owner = str.ReadString();
  obj.bloblen = str.length;
  obj.blob = str.Increment(obj.bloblen);
  
}




void DB_FindAuthority(const char* auth,void* thisptr, void(*callback)(void*,unsigned char*,size_t));

static inline void* DB_FindAuthority(const char* auth) {
  void* a;
  void(*b)(void*,unsigned char*,size_t);
  void* retval = 0;
  a = System::ABI::C([&](unsigned char* data, size_t len){
    retval = RSA_Key(data,len);
  },b);
  DB_FindAuthority(auth,a,b);
  return retval;
}


void DB_ObjectLookup(const char* id,void* thisptr, void(*callback)(void*,const NamedObject&));
void DB_FindByName(const char* name, const char* parentID, void* thisptr, void(*callback)(void*,const NamedObject&));
/**
 * @summary Attempts to insert a raw NamedObject into the database. Assumes that object has already been sanity-checked.
 * */
void DB_Insert(const NamedObject& obj);

void DB_Insert_Certificate(const char* thumbprint,const unsigned char* cert, size_t bytes, bool isPrivate);

void DB_EnumPrivateKeys(void* thisptr,bool(*callback)(void*,unsigned char*, size_t));
}
#endif