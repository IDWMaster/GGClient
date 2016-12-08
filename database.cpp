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
#include "database.h"
#include "sqlite3.h"

#include <string.h>

#include <mutex>
#include <openssl/rsa.h>
#include <openssl/sha.h>


namespace GlobalGrid {
static std::mutex mtx;

class Database {
public:
    sqlite3* db;
    sqlite3_stmt* getobj;
    sqlite3_stmt* findobj;
    sqlite3_stmt* addobj;
    sqlite3_stmt* findauth;
    sqlite3_stmt* addauth;
    sqlite3_stmt* enumprivate;
  Database() {
    sqlite3_open("freespeech_db",&db);
    const char* parsed;
    const char* stmt = "SELECT * FROM DHT WHERE ID = ?";
    sqlite3_prepare(db,stmt,strlen(stmt),&getobj,&parsed);
    stmt = "SELECT * FROM DHT WHERE Name = ? AND Parent = ?";
    sqlite3_prepare(db,stmt,strlen(stmt),&findobj,&parsed);
    stmt = "INSERT INTO DHT VALUES (?, ?, ?, ?, ?)";
    sqlite3_prepare(db,stmt,strlen(stmt),&addobj,&parsed);
    stmt = "SELECT * FROM Certificates WHERE Thumbprint = ?";
    sqlite3_prepare(db,stmt,strlen(stmt),&findauth,&parsed);
    stmt = "INSERT INTO Certificates VALUES (?, ?, ?)";
    sqlite3_prepare(db,stmt,strlen(stmt),&addauth,&parsed);
    stmt = "SELECT * FROM Certificates WHERE isPrivate = 1";
    sqlite3_prepare(db,stmt,strlen(stmt),&enumprivate,&parsed);
    
    
  }
};


static Database db;

void DB_EnumPrivateKeys(void* thisptr,bool(*callback)(void*,unsigned char*, size_t))
{
  std::unique_lock<std::mutex> l(mtx);
  int val = -1;
  while((val = sqlite3_step(db.enumprivate)) != SQLITE_DONE) {
    
    if(val == SQLITE_ROW) {
    if(!callback(thisptr,(unsigned char*)sqlite3_column_blob(db.enumprivate,1),sqlite3_column_bytes(db.enumprivate,1))) {
      break;
    }
    }
  }
  sqlite3_reset(db.enumprivate);
}




void DB_ObjectLookup(const char* id,void* thisptr, void(*callback)(void*,const NamedObject&))
{
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.getobj,1,id,strlen(id),0);
  int val;
  while((val = sqlite3_step(db.getobj)) != SQLITE_DONE) {
   if(val == SQLITE_ROW) {
     NamedObject obj;
     obj.id = (char*)sqlite3_column_text(db.getobj,0);
     obj.owner = (char*)sqlite3_column_text(db.getobj,1);
     obj.name = (char*)sqlite3_column_text(db.getobj,2);
     obj.parent = (char*)sqlite3_column_text(db.getobj,3);
     obj.blob  = (unsigned char*)sqlite3_column_blob(db.getobj,4);
     obj.bloblen = sqlite3_column_bytes(db.getobj,5);
     callback(thisptr,obj);
     break;
   }
  }
  sqlite3_reset(db.getobj);
}
void DB_Insert(const NamedObject& obj)
{
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.addobj,1,obj.id,strlen(obj.id),0);
  sqlite3_bind_text(db.addobj,2,obj.owner,strlen(obj.owner),0);
  sqlite3_bind_text(db.addobj,3,obj.name,strlen(obj.name),0);
  sqlite3_bind_text(db.addobj,4,obj.parent,strlen(obj.parent),0);
  sqlite3_bind_blob(db.addobj,5,obj.blob,obj.bloblen,0);
  while(sqlite3_step(db.addobj) != SQLITE_DONE){};
  sqlite3_reset(db.addobj);
}

void DB_FindAuthority(const char* auth,void* thisptr, void(*callback)(void*,unsigned char*,size_t)) {
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.findauth,1,auth,strlen(auth),0);
  int val;
  while((val = sqlite3_step(db.findauth)) != SQLITE_DONE) {
    if(val == SQLITE_ROW) {
      
      callback(thisptr,(unsigned char*)sqlite3_column_blob(db.findauth,1),sqlite3_column_bytes(db.findauth,1));
      break;
    }
  }
  sqlite3_reset(db.findauth);
}

void DB_Insert_Certificate(const char* thumbprint,const unsigned char* cert, size_t bytes, bool isPrivate) {
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.addauth,1,thumbprint,strlen(thumbprint),0);
  sqlite3_bind_blob(db.addauth,2,cert,bytes,0);
  sqlite3_bind_int(db.addauth,3,isPrivate);
  while(sqlite3_step(db.addauth) != SQLITE_DONE){};
  sqlite3_reset(db.addauth);
}

void DB_FindByName(const char* name, const char* parentID,void* thisptr,void(*callback)(void*,const NamedObject&))
{
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.findobj,1,name,strlen(name),0);
  sqlite3_bind_text(db.findobj,2,parentID,strlen(parentID),0);
  
  
  
  int val;
  //NOTE: We could get multiple results here. There may be a number of entities claiming to own a given parent,name key.
  //This is fine; as there may exist many different authority trees.
  
  while((val = sqlite3_step(db.findobj)) != SQLITE_DONE) {
   if(val == SQLITE_ROW) {
     NamedObject obj;
     obj.id = (char*)sqlite3_column_text(db.findobj,0);
     obj.owner = (char*)sqlite3_column_text(db.findobj,1);
     obj.name = (char*)sqlite3_column_text(db.findobj,2);
     obj.parent = (char*)sqlite3_column_text(db.findobj,3);
     obj.blob  = (unsigned char*)sqlite3_column_blob(db.findobj,4);
     obj.bloblen = sqlite3_column_bytes(db.findobj,5);
     callback(thisptr,obj);
     
   }
}
sqlite3_reset(db.findobj);
}

}