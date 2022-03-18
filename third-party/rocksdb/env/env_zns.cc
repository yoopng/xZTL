//  Copyright (c) 2019, Samsung Electronics.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
//  Written by Ivan L. Picoli <i.picoli@samsung.com>
#include <sys/time.h>
#include <iostream>
#include <memory>

#include "env/env_zns.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"

#define FILE_METADATA_BUF_SIZE (80 * 1024 * 1024)
#define FLUSH_INTERVAL (60 * 60)
#define SLEEP_TIME 5
#define MAX_META_ZONE 2

enum Operation {All, Update, Replace, Delete};

namespace rocksdb {

std::uint32_t ZNSFile::GetFileMetaLen() {
  uint32_t metaLen = sizeof(ZrocksFileMeta);
  metaLen += pieceInfos.size() * sizeof(PieceInfo);
  return metaLen;
}

std::uint32_t ZNSFile::WriteMetaToBuf(unsigned char* buf, bool update) {
  // reserved single file head
  std::uint32_t length = sizeof(ZrocksFileMeta);

  ZrocksFileMeta fileMetaData;
  fileMetaData.filesize = size;
  fileMetaData.level = level;
  fileMetaData.pieceNum = pieceInfos.size();
  std::uint32 i = 0;
  if (update) {
	i = startIndex;
	fileMetaData.pieceNum = pieceInfos.size() - startIndex;
  }
  
  memcpy(fileMetaData.filename, name.c_str(), name.length());
  memcpy(buf, &fileMetaData, sizeof(ZrocksFileMeta));
  for (; i < pieceInfos.size(); i++) {
 	memcpy(buf, &pieceInfos[i], sizeof(PieceInfo));
	length += sizeof(PieceInfo);
  }

  if (update) {
	startIndex = pieceInfos.size();
  }
 
  return length;
}

void ZNSFile::PrintMetaData() {
  std::cout << __func__ << " FileName: " << name << std::endl;
  for (uint32_t i =0; i < pieceInfos.size(); i++) {
  	PieceInfo& pInfo = pieceInfos[i];
  	std::cout << " nodeId: " << pInfo.node_id << " offset: " << pInfo.p.pos <<  " len: " << pInfo.p.len <<std::endl;
  }
}
/* ### ZNS Environment method implementation ### */
void ZNSEnv::NodeSta(std::int32_t znode_id, size_t n) {
  double seconds;

  if (start_ns == 0) {
    GET_NANOSECONDS(start_ns, ts_s);
  }

  read_bytes[znode_id] += n;

  GET_NANOSECONDS(end_ns, ts_e);
  seconds = (double)(end_ns - start_ns) / (double)1000000000;  // NOLINT
  int totalcnt = 0, readcnt = 0;
  if (seconds >= 2) {
    for (int i = 0; i < ZNS_MAX_NODE_NUM; i++) {
      if (alloc_flag[i]) {
        totalcnt++;
      }
    }

    for (int i = 0; i < ZNS_MAX_NODE_NUM; i++) {
      if (read_bytes[i]) {
        readcnt++;
        read_bytes[i] = 0;
      }
    }

    GET_NANOSECONDS(start_ns, ts_s);
  }
}

Status ZNSEnv::NewSequentialFile(const std::string& fname,
                                 std::unique_ptr<SequentialFile>* result,
                                 const EnvOptions& options) {
  if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;

  if (IsFilePosix(fname)) {
    return posixEnv->NewSequentialFile(fname, result, options);
  }

  result->reset();

  ZNSSequentialFile* f = new ZNSSequentialFile(fname, this, options);
  result->reset(dynamic_cast<SequentialFile*>(f));

  return Status::OK();
}

Status ZNSEnv::NewRandomAccessFile(const std::string& fname,
                                   std::unique_ptr<RandomAccessFile>* result,
                                   const EnvOptions& options) {
  if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;

  if (IsFilePosix(fname)) {
    return posixEnv->NewRandomAccessFile(fname, result, options);
  }

  ZNSRandomAccessFile* f = new ZNSRandomAccessFile(fname, this, options);
  result->reset(dynamic_cast<RandomAccessFile*>(f));

  return Status::OK();
}

Status ZNSEnv::NewWritableFile(const std::string& fname,
                               std::unique_ptr<WritableFile>* result,
                               const EnvOptions& options) {
  if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;

  uint32_t fileNum = 0;

  if (IsFilePosix(fname)) {
    return posixEnv->NewWritableFile(fname, result, options);
  } else {
    posixEnv->NewWritableFile(fname, result, options);
  }

  ZNSWritableFile* f = new ZNSWritableFile(fname, this, options, 0);
  result->reset(dynamic_cast<WritableFile*>(f));

  filesMutex.Lock();
  fileNum = files.count(fname);
  if (fileNum != 0) {
    delete files[fname];
    files.erase(fname);
  }

  files[fname] = new ZNSFile(fname, 0);
  files[fname]->uuididx = uuididx++;
  filesMutex.Unlock();

  return Status::OK();
}

Status ZNSEnv::NewWritableLeveledFile(const std::string& fname,
                                      std::unique_ptr<WritableFile>* result,
                                      const EnvOptions& options, int level) {
  if (ZNS_DEBUG)
    std::cout << __func__ << ":" << fname << " lvl: " << level << std::endl;

  uint32_t fileNum = 0;

  if (IsFilePosix(fname)) {
    return posixEnv->NewWritableFile(fname, result, options);
  } else {
    posixEnv->NewWritableFile(fname, result, options);
  }

  if (level < 0) {
    return NewWritableFile(fname, result, options);
  }

  ZNSWritableFile* f = new ZNSWritableFile(fname, this, options, level);
  result->reset(dynamic_cast<WritableFile*>(f));

  filesMutex.Lock();
  fileNum = files.count(fname);
  if (fileNum != 0) {
    delete files[fname];
    files.erase(fname);
  }

  files[fname] = new ZNSFile(fname, level);
  files[fname]->uuididx = uuididx++;
  filesMutex.Unlock();

  return Status::OK();
}

Status ZNSEnv::DeleteFile(const std::string& fname) {
  if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;

  if (IsFilePosix(fname)) {
    return posixEnv->DeleteFile(fname);
  }
  posixEnv->DeleteFile(fname);

#if !ZNS_OBJ_STORE
  filesMutex.Lock();
  if (files.find(fname) == files.end() || files[fname] == NULL) {
    filesMutex.Unlock();
    return Status::OK();
  }

  if (files[fname]->znode_id != -1) zrocks_trim(files[fname]->znode_id);

  delete files[fname];
  files.erase(fname);
  FlushMetaData();
  filesMutex.Unlock();
#endif

  return Status::OK();
}

Status ZNSEnv::GetFileSize(const std::string& fname, std::uint64_t* size) {
  if (IsFilePosix(fname)) {
    if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;
    return posixEnv->GetFileSize(fname, size);
  }

  filesMutex.Lock();
  if (files.find(fname) == files.end() || files[fname] == NULL) {
    filesMutex.Unlock();
    return Status::OK();
  }

  if (ZNS_DEBUG)
    std::cout << __func__ << ":" << fname << "size: " << files[fname]->size
              << std::endl;

  *size = files[fname]->size;
  filesMutex.Unlock();

  return Status::OK();
}

Status ZNSEnv::GetFileModificationTime(const std::string& fname,
                                       std::uint64_t* file_mtime) {
  if (ZNS_DEBUG) std::cout << __func__ << ":" << fname << std::endl;

  if (IsFilePosix(fname)) {
    return posixEnv->GetFileModificationTime(fname, file_mtime);
  }

  /* TODO: Get SST files modification time from ZNS */
  *file_mtime = 0;

  return Status::OK();
}

Status ZNSEnv::FlushMetaData() {
  if (!ZNS_META_SWITCH) {
    return Status::OK();
  }

  memset(metaBuf, 0, FILE_METADATA_BUF_SIZE);
  // reserved head position
  int dataLen = sizeof(MetadataHead) + sizeof(fileNum);
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " Start FlushMetaData " << std::endl;
  int fileNum = 0;
  std::map<std::string, ZNSFile*>::iterator itermap = files.begin();
  for (; itermap != files.end(); ++itermap) {
    ZNSFile* zfile = itermap->second;
    if (zfile == NULL) {
      continue;
    }

    fileNum++;
    if (ZNS_DEBUG_META) zfile->PrintMetaData();
    if (dataLen + zfile->GetFileMetaLen() >= FILE_METADATA_BUF_SIZE) {
      std::cout << __func__ << ": buf over flow" << std::endl;
      return Status::MemoryLimit();
    }

    int length = zfile->WriteMetaToBuf(metaBuf + dataLen);
    dataLen += length;
  }

  // sector align
  if (dataLen % ZNS_ALIGMENT != 0) {
    dataLen = (dataLen / ZNS_ALIGMENT + 1) * ZNS_ALIGMENT;
  }

  MetadataHead metadataHead;
  metadataHead.crc = 0;
  metadataHead.tag = All;
  metadataHead.dataLength = dataLen - sizeof(MetadataHead);
  memcpy(metaBuf, &metadataHead, sizeof(MetadataHead));
  memcpy(metaBuf+sizeof(MetadataHead), &fileNum, sizeof(fileNum));
  int ret = zrocks_write_file_metadata(metaBuf, dataLen);
  if (ret) {
    std::cout << __func__ << ": zrocks_write_metadata error" << std::endl;
  }
 
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " End FlushMetaData " << std::endl;

  return Status::OK();
}

Status ZNSEnv::FlushUpdateMetaData(ZNSFile* zfile) {
  if (!ZNS_META_SWITCH) {
    return Status::OK();
  }

  memset(metaBuf, 0, FILE_METADATA_BUF_SIZE);
  // reserved head position
  int dataLen = sizeof(MetadataHead);
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " Start FlushUpdateMetaData " << std::endl;

    int length = zfile->WriteMetaToBuf(metaBuf + dataLen);
    dataLen += length;
  
  // sector align
  if (dataLen % ZNS_ALIGMENT != 0) {
    dataLen = (dataLen / ZNS_ALIGMENT + 1) * ZNS_ALIGMENT;
  }

  MetadataHead metadataHead;
  metadataHead.crc = 0;
  metadataHead.tag = Update;
  metadataHead.dataLength = dataLen - sizeof(MetadataHead);
  memcpy(metaBuf, &metadataHead, sizeof(MetadataHead));
  int ret = zrocks_write_file_metadata(buf, dataLen);
  if (ret) {
    std::cout << __func__ << ": zrocks_write_metadata error" << std::endl;
  }
  
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " End FlushUpdateMetaData " << std::endl;

  return Status::OK();
}

Status ZNSEnv::FlushDelMetaData(std::string& fileName) {
  if (!ZNS_META_SWITCH) {
    return Status::OK();
  }

  memset(metaBuf, 0, FILE_METADATA_BUF_SIZE);
  // reserved head position
  int dataLen = sizeof(MetadataHead);
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " Start FlushUpdateMetaData " << std::endl;

  memcpy(metaBuf + dataLen, fileName.c_str(), fileName.length());
  dataLen += FILE_NAME_LEN;
	
  // sector align
  if (dataLen % ZNS_ALIGMENT != 0) {
    dataLen = (dataLen / ZNS_ALIGMENT + 1) * ZNS_ALIGMENT;
  }

  MetadataHead metadataHead;
  metadataHead.crc = 0;
  metadataHead.tag = Delete;
  metadataHead.dataLength = dataLen - sizeof(MetadataHead);
  memcpy(metaBuf, &metadataHead, sizeof(MetadataHead));
  int ret = zrocks_write_file_metadata(buf, dataLen);
  if (ret) {
    std::cout << __func__ << ": zrocks_write_metadata error" << std::endl;
  }
  
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " End FlushUpdateMetaData " << std::endl;

  return Status::OK();
}

Status ZNSEnv::FlushReplaceMetaData(std::string& srcName, std::string& destName) {
  if (!ZNS_META_SWITCH) {
    return Status::OK();
  }

  memset(metaBuf, 0, FILE_METADATA_BUF_SIZE);
  // reserved head position
  int dataLen = sizeof(MetadataHead);
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " Start FlushReplaceMetaData " << std::endl;

  memcpy(metaBuf + dataLen, srcName.c_str(), srcName.length());
  dataLen += FILE_NAME_LEN;
  
  memcpy(metaBuf + dataLen, destName.c_str(), destName.length());
  dataLen += FILE_NAME_LEN;
  
  // sector align
  if (dataLen % ZNS_ALIGMENT != 0) {
    dataLen = (dataLen / ZNS_ALIGMENT + 1) * ZNS_ALIGMENT;
  }

  MetadataHead metadataHead;
  metadataHead.crc = 0;
  metadataHead.tag = Replace;
  metadataHead.dataLength = dataLen - sizeof(MetadataHead);
  memcpy(metaBuf, &metadataHead, sizeof(MetadataHead));
  int ret = zrocks_write_file_metadata(buf, dataLen);
  if (ret) {
    std::cout << __func__ << ": zrocks_write_metadata error" << std::endl;
  }
  
  if (ZNS_DEBUG_META)
    std::cout << __func__ << " End FlushUpdateMetaData " << std::endl;

  return Status::OK();
}

void ZNSEnv::RecoverFileFromBuf(unsigned char* buf, std::uint32_t& praseLen) {
  praseLen = 0;
  ZrocksFileMeta fileMetaData = *(reinterpret_cast<ZrocksFileMeta*>(buf));
  if (fileMetaData.magic != FILE_METADATA_MAGIC) {
    std::cout << __func__ << ": fileMetaData magic error" << std::endl;
    return;
  }

  ZNSFile* znsFile = NULL;
  znsFile = new ZNSFile(fileMetaData.filename, -1);
  if (znsFile == NULL) {
    return;
  }

  znsFile->size = fileMetaData.filesize;
  znsFile->level = fileMetaData.level;
 
  std::uint32_t len = sizeof(ZrocksFileMeta);
  for (std::uint16_t i = 0; i < fileMetaData.pieceNum; i++) {
	PieceInfo p = *(reinterpret_cast<PieceInfo*>(buf));
	znsFile->pieceInfos.push_back(p);
	len += sizeof(PieceInfo);
  }
  
  if (ZNS_DEBUG_META) {
    znsFile->PrintMetaData();
  }

  filesMutex.Lock();
  files[znsFile->name] = znsFile;
  filesMutex.Unlock();

  praseLen = len;
}

Status ZNSEnv::LoadMetaData() {
  metaBuf = reinterpret_cast<unsigned char*>(zrocks_alloc(FILE_METADATA_BUF_SIZE));
  if (metaBuf == NULL) {
	return Status::MemoryLimit();
  }

  std::cout << __func__ << " Start LoadMetaData " << std::endl;
  
  std::uint8_t metaZoneNum = MAX_META_ZONE;
  MetaZone metaZones[MAX_META_ZONE]={0};
  int ret = zrocks_get_metadata_slbas(&metaZoneNum, metaZones);
  
  SuperBlock masterSB;
  masterZone = metaZones[0];
  ret = zrocks_read_metadata(metaZones[0].slba, (unsigned char*)&masterSB, sizeof(SuperBlock));
  if (ret || masterSB.info.magic != METADATA_MAGIC) {
	std::cout << "read superblock err" << std::endl;
  }
  
  SuperBlock slaveSB;
  slaveZone = metaZones[1];
  ret = zrocks_read_metadata(metaZones[1].slba, (unsigned char*)&slaveSB, sizeof(SuperBlock));
  if (ret || slaveSB.info.magic != METADATA_MAGIC) {
	std::cout << "read superblock err" << std::endl;
  }
  
  if (masterSB.info.sequence > slaveSB.info.sequence) {
	seq = masterSB.info.sequence + 1;
  } else {
	seq = slaveSB.info.sequence + 1;
	masterZone = metaZones[1];
	slaveZone = metaZones[0];
  }
  
  std::uint64_t slbas[MAX_META_ZONE]; 
  slbas[0] = masterZone.slba;
  slbas[1] = slaveZone.slba;

  for (std::uint8_t i = 0; i < MAX_META_ZONE; i++) {
	  std::uint64_t readSlba = slbas[i] + (sizeof(SuperBlock) / ZNS_ALIGMENT);
	  std::uint32_t praseLen = 0;
	  while (true) {
	  	  int readLen = ZNS_ALIGMENT;
		  ret = zrocks_read_metadata(readSlba, metaBuf, readLen);
		  if (ret) {
			std::cout << __func__ << ":  zrocks_read_metadata head error" << std::endl;
			break;
		  }

		  MetadataHead* metadataHead = (MetadataHead*)metaBuf;
		  if (metadataHead->dataLength == 0) {
			return;
		  }
		  
		  if (metadataHead->dataLength > readLen) {
			 ret = zrocks_read_metadata(readSlba, metaBuf + readLen, metadataHead->dataLength - readLen);
			if (ret) {
				std::cout << __func__ << ":  zrocks_read_metadata head error" << std::endl;
				continue;
		  	}
		  }
		  // Ð£ÑéCRC
		 praseLen += sizeof(MetadataHead);
		 readSlba += metadataHead->dataLength / ZNS_ALIGMENT;
		 switch (metadataHead->tag) {
		     case All:
			 	std::uint16_t fileNum = *(std::uint16_t*)(metaBuf + praseLen);
				praseLen += sizeof(fileNum);
				for (std::uint16_t i = 0; i < fileNum; i++) {
					std::uint32_t fileMetaLen = 0;
					RecoverFileFromBuf(metaBuf+ praseLen, fileMetaLen);
					praseLen += fileMetaLen;
				}
			 break;
		     case Update:
			 	std::uint32_t fileMetaLen = 0;
			 	RecoverFileFromBuf(metaBuf+ praseLen, fileMetaLen);
				praseLen += fileMetaLen;
	                break;
	            case Replace:
				std::string srcFileName = metaBuf+ praseLen;
				praseLen += FILE_NAME_LEN;
				std::string dstFileName = metaBuf+ praseLen;
				praseLen += FILE_NAME_LEN;
				ZNSFile* znsFile = files[srcFileName];
				files.erase(srcFileName);
				files[dstFileName] =znsFile;
	                break;
		     case Delete:
			 	std::string fileName = metaBuf+ praseLen;
				praseLen += FILE_NAME_LEN;
				files.erase(fileName);
	                break;
	            default:
	                break;
	         }
	  }

  }

  std::cout << __func__ << " End LoadMetaData " << std::endl;
  return Status::OK();
}

/* ### The factory method for creating a ZNS Env ### */
Status NewZNSEnv(Env** zns_env, const std::string& dev_name) {
  static ZNSEnv znsenv(dev_name);
  ZNSEnv* znsEnv = &znsenv;
  *zns_env = znsEnv;

#if !ZNS_OBJ_STORE
  znsEnv->envStartMutex.Lock();
  if (znsEnv->isEnvStart) {
    znsEnv->envStartMutex.Unlock();
    return Status::OK();
  }

  // Load metaData
  Status status = znsEnv->LoadMetaData();
  if (!status.ok()) {
    znsEnv->envStartMutex.Unlock();
    std::cout << __func__ << ": znsEnv LoadMetaData error" << std::endl;
    return Status::IOError();
  }

  znsEnv->envStartMutex.Unlock();
#endif

  return Status::OK();
}

}  // namespace rocksdb
