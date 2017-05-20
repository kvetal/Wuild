/*
 * Copyright (C) 2017 Smirnov Vladimir mapron1@gmail.com
 * Source code licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 or in file COPYING-APACHE-2.0.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.h
 */

#include "FileUtils.h"

#include "Compression.h"
#include "Syslogger.h"
#include "ThreadUtils.h"

#include <assert.h>
#include <stdio.h>
#include <algorithm>
#include <fstream>
#include <streambuf>

#ifdef HAS_BOOST
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#define u8string string
using fserr = boost::system::error_code;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
using fserr = std::error_code;
#endif

#ifdef _MSC_VER
#define strtoull _strtoui64
#define getcwd _getcwd
#define PATH_MAX _MAX_PATH
#endif

#if defined( _WIN32)
#include <windows.h>
#include <io.h>
#include <share.h>
#include <direct.h>
#else
#include <unistd.h>
#include <errno.h>
inline int GetLastError() { return errno; }
#endif

namespace {
static const size_t CHUNK = 16384;
}


namespace Wuild {

class FileInfoPrivate
{
public:
	fs::path m_path;
};

std::string FileInfo::ToPlatformPath(std::string path)
{
#ifdef _WIN32
   std::replace(path.begin(), path.end(), '/', '\\');
   std::transform(path.begin(), path.end(), path.begin(), [](char c) { return ::tolower(c);});
#endif
   return path;
}

FileInfo::FileInfo(const FileInfo &rh)
	: m_impl(new FileInfoPrivate(*rh.m_impl))
{

}

FileInfo &FileInfo::operator =(const FileInfo &rh)
{
	m_impl.reset(new FileInfoPrivate(*rh.m_impl));
	return *this;
}

FileInfo::FileInfo(const std::string &filename)
	: m_impl(new FileInfoPrivate())
{
	m_impl->m_path = filename;
}

FileInfo::~FileInfo()
{

}

void FileInfo::SetPath(const std::string &path)
{
	m_impl->m_path = path;
}

std::string FileInfo::GetPath() const
{
	return m_impl->m_path.u8string();
}

std::string FileInfo::GetDir(bool ensureEndSlash) const
{
	auto ret = m_impl->m_path.parent_path().u8string();
	if (!ret.empty() && ensureEndSlash)
		ret += '/';
	return ret;
}

std::string FileInfo::GetFullname() const
{
	return m_impl->m_path.filename().u8string();
}

std::string FileInfo::GetNameWE() const
{
	const auto name = this->GetFullname();
	const auto dot = name.find('.');
	return name.substr(0, dot);
}

std::string FileInfo::GetFullExtension() const
{
	const auto name = this->GetFullname();
	const auto dot = name.find('.');
	return name.substr( dot );
}

std::string FileInfo::GetPlatformShortName() const
{
#ifdef _WIN32
	std::string result = GetPath();
	fserr code;
	result = fs::canonical(result, code).u8string();
	long length = 0;

	// First obtain the size needed by passing NULL and 0.
	length = GetShortPathNameA(result.c_str(), nullptr, 0);
	if (length == 0)
		return result;

	// Dynamically allocate the correct size
	// (terminating null char was included in length)
	std::vector<char> buffer(length + 1);

	// Now simply call again using same long path.
	length = GetShortPathNameA(result.c_str(), buffer.data(), length);
	if (length == 0)
		return result;

	return ToPlatformPath(std::string(buffer.data(), length));
#else
	return GetPath();
#endif
}


bool FileInfo::ReadCompressed(ByteArrayHolder &data, CompressionInfo compressionInfo)
{
	std::ifstream inFile;
	inFile.open(GetPath().c_str(), std::ios::binary | std::ios::in);
	if (!inFile)
		return false;

	data.m_filename = m_impl->m_path.filename().u8string();
	// TODO: maybe use in-memory buffer for uncompressed reading???
	inFile.seekg (0, inFile.end);
	size_t length = inFile.tellg();
	inFile.seekg (0, inFile.beg);

	if (length)
	{
		std::vector<char> bufferCRC(length);
		inFile.read (bufferCRC.data(), length);
		inFile.seekg (0, inFile.beg);

		data.m_uncompressedSize = length;
		data.m_uncompressedCRC = CRC32(bufferCRC.data(), length);
	}

	try
	{
		ReadCompressedData(inFile, data, compressionInfo);

		data.m_compressedCRC = CRC32(data.data(), data.size());
	}
	catch(std::exception &e)
	{
		Syslogger(Syslogger::Err) << "Error on reading:" << e.what() << " for " << GetPath();
		return false;
	}

	if (Syslogger::IsLogLevelEnabled(Syslogger::Debug))
		Syslogger() << "Compressed " << this->GetPath() << ": " << this->GetFileSize() << " -> " << data.size();

	return true;
}

#define EXCEPTION_ASSERT(EXPR, EX) do { assert(EXPR); if (!(EXPR)) throw (EX); } while (false)

bool FileInfo::WriteCompressed(const ByteArrayHolder & data, CompressionInfo compressionInfo, bool createTmpCopy)
{
	ByteArrayHolder uncompData;
	try
	{
		Syslogger(Syslogger::Notice) << "Write " << fs::absolute(m_impl->m_path).u8string() << " with cmp=" << uint32_t(compressionInfo.m_type);
		UncompressDataBuffer(data, uncompData, compressionInfo);

		size_t uncompressedSize = uncompData.size();
		uint32_t uncompressedCrc = CRC32(uncompData.data(), uncompressedSize);
		EXCEPTION_ASSERT(uncompressedSize == data.m_uncompressedSize, std::runtime_error("uncompressedSize notEqual:" + std::to_string(uncompressedSize) + "!=" + std::to_string(data.m_uncompressedSize)));
		EXCEPTION_ASSERT(uncompressedCrc == data.m_uncompressedCRC,   std::runtime_error("uncompressedCrc notEqual:"  + std::to_string(uncompressedCrc) + "!=" + std::to_string(data.m_uncompressedCRC)));
	}
	catch(std::exception &e)
	{
		Syslogger(Syslogger::Err) << "Error on uncompress:" << e.what() << " for " << GetPath();
		return false;
	}

	return this->WriteFile(uncompData, createTmpCopy);
}

bool FileInfo::ReadFile(ByteArrayHolder &data)
{
	FILE * f = fopen(GetPath().c_str(), "rb");
	if (!f)
		return false;

	ByteArray& dest = data.ref();

	unsigned char in[CHUNK];
	do {
		auto avail_in = fread(in, 1, CHUNK, f);
		if (!avail_in || ferror(f)) break;
		dest.insert(dest.end(), in, in + avail_in);
		if (feof(f)) break;

	} while (true);

	fclose(f);
	return true;
}

bool FileInfo::WriteFile(const ByteArrayHolder &data, bool createTmpCopy)
{
	const std::string originalPath = fs::absolute(m_impl->m_path).u8string();
	const std::string writePath = createTmpCopy ? originalPath + ".tmp" : originalPath;
	this->Remove();

	try
	{
#ifndef _WIN32
		std::ofstream outFile;
		outFile.open(writePath, std::ios::binary | std::ios::out);
		outFile.write((const char*)data.data(), data.size());
		outFile.close();
#else
		auto fileHandle = CreateFileA((LPTSTR) writePath.c_str(), // file name
							   GENERIC_WRITE,        // open for write
							   0,                    // do not share
							   NULL,                 // default security
							   CREATE_ALWAYS,        // overwrite existing
							   FILE_ATTRIBUTE_NORMAL,// normal file
							   NULL);                // no template
		if (fileHandle == INVALID_HANDLE_VALUE)
			throw std::runtime_error("Failed to open file");

		size_t bytesToWrite = data.size(); // <- lossy

		size_t totalWritten = 0;
		do {
			auto blockSize = std::min(bytesToWrite, size_t(32 * 1024 * 1024));
			DWORD bytesWritten;
			if (!::WriteFile(fileHandle, data.data() + totalWritten, blockSize, &bytesWritten, NULL)) {
				if (totalWritten == 0) {
					// Note: Only return error if the first WriteFile failed.
					throw std::runtime_error("Failed to write data");
				}
				break;
			}
			if (bytesWritten == 0)
				break;
			totalWritten += bytesWritten;
			bytesToWrite -= bytesWritten;
		} while (totalWritten < data.size());

		if (!::CloseHandle(fileHandle))
			throw std::runtime_error("Failed to close file");

#endif
	}
	catch(std::exception &e)
	{
		Syslogger(Syslogger::Err) << "Error on writing:" << e.what() << " for " << writePath ;
		return false;
	}
	if (createTmpCopy)
	{
		fserr code;
		fs::rename(writePath, originalPath, code);
		if (code)
		{
			Syslogger(Syslogger::Err) << "Failed to rename " << writePath << " -> " << originalPath << " :" << GetLastError();
			return false;
		}
	}
	return true;
}

bool FileInfo::Exists()
{
	fserr code;
	return fs::exists(m_impl->m_path, code);
}

size_t FileInfo::GetFileSize()
{
	if (!Exists())
		return 0;

	fserr code;
	return fs::file_size(m_impl->m_path, code);
}

void FileInfo::Remove()
{
	fserr code;
	if (fs::exists(m_impl->m_path, code))
		fs::remove(m_impl->m_path, code);
}

void FileInfo::Mkdirs()
{
	fserr code;
	fs::create_directories(m_impl->m_path, code);
}

StringVector FileInfo::GetDirFiles(bool sortByName)
{
	StringVector res;
	for(const fs::directory_entry& it : fs::directory_iterator(m_impl->m_path))
	{
		 const fs::path& p = it.path();
		 if (fs::is_regular_file(p))
			res.push_back( p.filename().u8string() );
	}
	if (sortByName)
		std::sort(res.begin(), res.end());
	return res;
}

TemporaryFile::~TemporaryFile()
{
	this->Remove();
}

std::string GetCWD()
{
	std::vector<char> cwd;
	std::string workingDir;
	do
	{
		cwd.resize(cwd.size() + 1024);
		errno = 0;
	} while (!getcwd(&cwd[0], cwd.size()) && errno == ERANGE);
	if (errno != 0 && errno != ERANGE)
	{
		workingDir = ".";
	}
	else
	{
		workingDir = cwd.data();
		if (workingDir.empty())
			workingDir = ".";
	}
	std::replace(workingDir.begin(), workingDir.end(), '\\', '/');
	if (*workingDir.rbegin() != '/')
		workingDir += '/';

	return workingDir;
}

void SetCWD(const std::string &cwd)
{
	chdir(cwd.c_str());
}

static unsigned int uiCRC32_Table[256] = {
	0x00000000L, 0x77073096L, 0xEE0E612CL,
	0x990951BAL, 0x076DC419L, 0x706AF48FL,
	0xE963A535L, 0x9E6495A3L, 0x0EDB8832L,
	0x79DCB8A4L, 0xE0D5E91EL, 0x97D2D988L,
	0x09B64C2BL, 0x7EB17CBDL, 0xE7B82D07L,
	0x90BF1D91L, 0x1DB71064L, 0x6AB020F2L,
	0xF3B97148L, 0x84BE41DEL, 0x1ADAD47DL,
	0x6DDDE4EBL, 0xF4D4B551L, 0x83D385C7L,
	0x136C9856L, 0x646BA8C0L, 0xFD62F97AL,
	0x8A65C9ECL, 0x14015C4FL, 0x63066CD9L,
	0xFA0F3D63L, 0x8D080DF5L, 0x3B6E20C8L,
	0x4C69105EL, 0xD56041E4L, 0xA2677172L,
	0x3C03E4D1L, 0x4B04D447L, 0xD20D85FDL,
	0xA50AB56BL, 0x35B5A8FAL, 0x42B2986CL,
	0xDBBBC9D6L, 0xACBCF940L, 0x32D86CE3L,
	0x45DF5C75L, 0xDCD60DCFL, 0xABD13D59L,
	0x26D930ACL, 0x51DE003AL, 0xC8D75180L,
	0xBFD06116L, 0x21B4F4B5L, 0x56B3C423L,
	0xCFBA9599L, 0xB8BDA50FL, 0x2802B89EL,
	0x5F058808L, 0xC60CD9B2L, 0xB10BE924L,
	0x2F6F7C87L, 0x58684C11L, 0xC1611DABL,
	0xB6662D3DL, 0x76DC4190L, 0x01DB7106L,
	0x98D220BCL, 0xEFD5102AL, 0x71B18589L,
	0x06B6B51FL, 0x9FBFE4A5L, 0xE8B8D433L,
	0x7807C9A2L, 0x0F00F934L, 0x9609A88EL,
	0xE10E9818L, 0x7F6A0DBBL, 0x086D3D2DL,
	0x91646C97L, 0xE6635C01L, 0x6B6B51F4L,
	0x1C6C6162L, 0x856530D8L, 0xF262004EL,
	0x6C0695EDL, 0x1B01A57BL, 0x8208F4C1L,
	0xF50FC457L, 0x65B0D9C6L, 0x12B7E950L,
	0x8BBEB8EAL, 0xFCB9887CL, 0x62DD1DDFL,
	0x15DA2D49L, 0x8CD37CF3L, 0xFBD44C65L,
	0x4DB26158L, 0x3AB551CEL, 0xA3BC0074L,
	0xD4BB30E2L, 0x4ADFA541L, 0x3DD895D7L,
	0xA4D1C46DL, 0xD3D6F4FBL, 0x4369E96AL,
	0x346ED9FCL, 0xAD678846L, 0xDA60B8D0L,
	0x44042D73L, 0x33031DE5L, 0xAA0A4C5FL,
	0xDD0D7CC9L, 0x5005713CL, 0x270241AAL,
	0xBE0B1010L, 0xC90C2086L, 0x5768B525L,
	0x206F85B3L, 0xB966D409L, 0xCE61E49FL,
	0x5EDEF90EL, 0x29D9C998L, 0xB0D09822L,
	0xC7D7A8B4L, 0x59B33D17L, 0x2EB40D81L,
	0xB7BD5C3BL, 0xC0BA6CADL, 0xEDB88320L,
	0x9ABFB3B6L, 0x03B6E20CL, 0x74B1D29AL,
	0xEAD54739L, 0x9DD277AFL, 0x04DB2615L,
	0x73DC1683L, 0xE3630B12L, 0x94643B84L,
	0x0D6D6A3EL, 0x7A6A5AA8L, 0xE40ECF0BL,
	0x9309FF9DL, 0x0A00AE27L, 0x7D079EB1L,
	0xF00F9344L, 0x8708A3D2L, 0x1E01F268L,
	0x6906C2FEL, 0xF762575DL, 0x806567CBL,
	0x196C3671L, 0x6E6B06E7L, 0xFED41B76L,
	0x89D32BE0L, 0x10DA7A5AL, 0x67DD4ACCL,
	0xF9B9DF6FL, 0x8EBEEFF9L, 0x17B7BE43L,
	0x60B08ED5L, 0xD6D6A3E8L, 0xA1D1937EL,
	0x38D8C2C4L, 0x4FDFF252L, 0xD1BB67F1L,
	0xA6BC5767L, 0x3FB506DDL, 0x48B2364BL,
	0xD80D2BDAL, 0xAF0A1B4CL, 0x36034AF6L,
	0x41047A60L, 0xDF60EFC3L, 0xA867DF55L,
	0x316E8EEFL, 0x4669BE79L, 0xCB61B38CL,
	0xBC66831AL, 0x256FD2A0L, 0x5268E236L,
	0xCC0C7795L, 0xBB0B4703L, 0x220216B9L,
	0x5505262FL, 0xC5BA3BBEL, 0xB2BD0B28L,
	0x2BB45A92L, 0x5CB36A04L, 0xC2D7FFA7L,
	0xB5D0CF31L, 0x2CD99E8BL, 0x5BDEAE1DL,
	0x9B64C2B0L, 0xEC63F226L, 0x756AA39CL,
	0x026D930AL, 0x9C0906A9L, 0xEB0E363FL,
	0x72076785L, 0x05005713L, 0x95BF4A82L,
	0xE2B87A14L, 0x7BB12BAEL, 0x0CB61B38L,
	0x92D28E9BL, 0xE5D5BE0DL, 0x7CDCEFB7L,
	0x0BDBDF21L, 0x86D3D2D4L, 0xF1D4E242L,
	0x68DDB3F8L, 0x1FDA836EL, 0x81BE16CDL,
	0xF6B9265BL, 0x6FB077E1L, 0x18B74777L,
	0x88085AE6L, 0xFF0F6A70L, 0x66063BCAL,
	0x11010B5CL, 0x8F659EFFL, 0xF862AE69L,
	0x616BFFD3L, 0x166CCF45L, 0xA00AE278L,
	0xD70DD2EEL, 0x4E048354L, 0x3903B3C2L,
	0xA7672661L, 0xD06016F7L, 0x4969474DL,
	0x3E6E77DBL, 0xAED16A4AL, 0xD9D65ADCL,
	0x40DF0B66L, 0x37D83BF0L, 0xA9BCAE53L,
	0xDEBB9EC5L, 0x47B2CF7FL, 0x30B5FFE9L,
	0xBDBDF21CL, 0xCABAC28AL, 0x53B39330L,
	0x24B4A3A6L, 0xBAD03605L, 0xCDD70693L,
	0x54DE5729L, 0x23D967BFL, 0xB3667A2EL,
	0xC4614AB8L, 0x5D681B02L, 0x2A6F2B94L,
	0xB40BBE37L, 0xC30C8EA1L, 0x5A05DF1BL,
	0x2D02EF8DL };

uint32_t CRC32(void *pData, size_t iLen)
{
	uint32_t uiCRC32 = 0xFFFFFFFF;
	unsigned char *pszData = (unsigned char*)pData;

	for (size_t i = 0; i<iLen; ++i)
		uiCRC32 = ((uiCRC32 >> 8) & 0x00FFFFFF) ^ uiCRC32_Table[(uiCRC32 ^ (unsigned int)*pszData++) & 0xFF];

	return (uiCRC32 ^ 0xFFFFFFFF);
}


}

