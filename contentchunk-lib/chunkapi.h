#ifndef _chunkapi_h
#define _chunkapi_h

#include <string>
#include <vector>
#include <map>
//#include <sqlite3.h>

using namespace std;
#include "chunkhash.h"

struct chunkMeta {
        std::string chunkid;
	std::string fpath;
	int fsize;
};

typedef std::vector <std::string> cid_list_t;

std::vector <std::string> contentChunkIDs(std::string file);// list of Chunked CIDs or NCIDs hexstrings from content
void print_chunklst(const vector<string>& cid_list_t);
void hex_digest(const unsigned char* digest, unsigned digest_len, char* hex_string, int hex_string_len);
cid_list_t put(const char *buffer, uint32_t size, uint32_t chunk_size, uint32_t ttl);
cid_list_t chunk_file(std::string filename, uint32_t chunk_size, uint32_t ttl);
bool pubkfile_exists(std::string path);
std::string get_keypath(std::string publisherName, int is_privkey);
std::string get_pubkey(std::string keypath);
std::pair<string, vector<uint8_t> > get_data_signature(std::string &xid, uint8_t* bytes,  size_t length, int sign_offset, string processType );
bool isValidSign(std::string publisherName, std::string content_URI,
                                const std::string &content,
                                const std::string &signature);
bool valid_chunk_signature (std::string ncid_sign, std::string &signature, size_t dSize, std::string datahex, std::vector<uint8_t>& data);
bool valid_chunk_data (std::string sCid, std::vector<uint8_t>& chunk_data);
std::vector<uint8_t> get_chunkdata(std::string cid, std::string processType,  size_t cSize);
std::tuple<string, std::vector<uint8_t>, size_t> load_chunk(std::string cid, std::vector<uint8_t>& data);
std::pair<string, uint8_t*> get_chunkhash(std::string cid, std::vector<uint8_t>& data);
map<std::string, chunkMeta> get_mapOfchunks (std::string path);
chunkhash_table* initHashtable (const vector<string>& cid_list_t);

#endif // _chunkapi_h
