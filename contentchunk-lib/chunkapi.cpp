#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/pem.h>
#include "chunkapi.h"
#include "Xsecurity.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <dirent.h>
#include <algorithm>
#include <string.h>
#include <stdlib.h>
#include <utility>
#include <tuple>

//#define WORKDIR "/home/testpath"  // default WORKDIR is user's home directory
#define CHUNKS_DIR "/picoquic/tmpChunks/"
#define SIGNATURE_BIN "/picoquic/tmpSignatureBin/"
const uint32_t default_chunk_size = 1024 * 1024;
const uint32_t default_ttl = 0;
#define TEST_CHUNK_SIZE 300
#include "headers/ncid_header.h"
#include "dagaddr.hpp"
#include "chunkhash.h"
#include <cmath>

#define XID_TYPE  "CID"

/**
 * STEP3. Helper Function
 * Generate the hex string from a SHA1 hash
 * @param digest - a buffer containing a SHA1 hash
 * @param digest_len length of digest. Must be SHA_DIGEST_LENGTH
 * @param hex_string a buffer to be filled in with SHA1 hash as a string
 * @param hex_string_len length of hex_string buffer
**/
void hex_digest(const unsigned char* digest, unsigned digest_len, char* hex_string, int hex_string_len)
{
    int i;
	assert(digest != NULL);
	assert(hex_string != NULL);
	assert(hex_string_len == SHA_DIGEST_LENGTH*2+1);
	assert(digest_len == SHA_DIGEST_LENGTH);
    for(i=0; i < digest_len; i++) {
        sprintf(&hex_string[2*i], "%02x", (unsigned int)digest[i]);
    }
    hex_string[hex_string_len-1] = '\0';
}


/**
 * Helper function: Retrieve Chunk data hash paired with its CID
 * @param cid   - hex string calculated from chunk
 * @return pair - hexstring of cid stored first with 
 *                chunkdata hash stored as second element
 * */

std::pair<string, uint8_t*> get_chunkhash(std::string cid, std::vector<uint8_t>& data)
{
        struct stat info;
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
		homepath.assign(WORKDIR);
        #endif

        std::string content_dir = homepath + CHUNKS_DIR;
        std::string path = content_dir + cid;
	unsigned char chunk_hash[SHA_DIGEST_LENGTH];
        std::pair<string, uint8_t*> chunk_pair;

	if ( valid_chunk_data (cid.c_str(), data)){
		if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
        	        cout << "Failed to located the file: " << cid.c_str() << endl;
                	return {};
        	}

		SHA1(data.data(), info.st_size, chunk_hash);
		chunk_pair.first=cid;
		chunk_pair.second=chunk_hash;

	cout <<"data path: " <<chunk_pair.first <<endl;
	cout<<"data hash: " <<endl <<chunk_pair.second <<endl;
	//cout<<"data" <<endl << data.data()<<endl;
	} 
	return chunk_pair;

}

/* getContent
 * @param cid   - content identfier
 * @return content data 
 * */

std::vector<uint8_t> get_chunkdata(std::string cid, size_t cSize)
{

    std::vector<uint8_t> cData;

    //Check to see if CID content is available on xcache local:
     std::string homepath = getenv("HOME");
     #ifdef WORKDIR
	homepath.assign(WORKDIR);
     #endif
     std::string CID_path = homepath + CHUNKS_DIR + cid;

     std::ifstream tmp_fin(CID_path.c_str(), std::ios::in | std::ios::binary);
     if (tmp_fin.good()){ //check if the file is local in the path

	     //start stream to prepare to sent to requester
             tmp_fin.seekg(0, std::ios::end); //take the lenghth of the file
             size_t f_size = tmp_fin.tellg();
             tmp_fin.seekg(0, std::ios::beg);

	     char dataCID[f_size];
             tmp_fin.read(dataCID, sizeof dataCID);
             tmp_fin.close();

             printf("Reading  %ld bytes of data \n", sizeof(dataCID));
             cData.insert(cData.begin(), dataCID, dataCID + sizeof(dataCID));
//	     cout<<"Data retrieved from chunkstorage :" <<cData.data()<<endl;
     } else
     {
	     cout<<"No matched Chunk Content found for "<<cid.c_str()<<endl;
     }
     return cData;
}

/**
 * Locate the chunk from disk by CID
 * @param cid   - hex string calculated from chunk
 * @return tuple  - inlude elements:chunkfile path to retrieve the chunk; chunkdata, and chunk datasize
 *                e.g. use std::get<0>(mytuple) to retrieve chunkfile path from returned mytuple
 * */

std::tuple<string, std::vector<uint8_t>, size_t> load_chunk(std::string cid, std::vector<uint8_t>& data)
{
	struct stat info;
	int rc;
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
	std::string content_dir = homepath + CHUNKS_DIR;
	std::string path = content_dir + cid;

	if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
		cout << "Failed to located the file: " << cid.c_str() << endl;
		return {};
	}
	cout << "Start fetching data from "<< path.c_str() << " of size " << info.st_size << endl;

	FILE *f = fopen(path.c_str(), "rb");

	data.reserve(info.st_size);
	int offset = 0;

	if (!f) {
		return {};
	}

	while (!feof(f)) {
		unsigned char *p = data.data();
		rc = fread(p + offset, 1, info.st_size, f);
		offset += rc;
	}

	std::vector<uint8_t> my_vector(&data[0], &data[offset]);
	auto chunkInfo =std::make_tuple(path,my_vector, info.st_size);
	fclose(f);
	
	return chunkInfo;
}

/**
 * Validate chunk signature does from publisher before load
 * @param ncid_sign - hex string of the ncid identifier, which is formed with hash hexstring of hash of (contentName+ pubkey), and
 * 		      hash of chunkdata. eg NCID:0238e29890bc2b6863bc284c9e9587de4b01db18::af39a018730b0acb32a75fd666880ba306efaf62 
 * @param publisherName - publisher Name
 * @param contentName -content Name
 * @param data -chunk data that signed
 * @return true if receiver 1). calculate NCID from requested publiser contentName match NCID hexstring of (Content+pubkey) located  
 * 			    2). hash of NCID content data recieved matches the NCID hexstring of chunk data hash
 * 			    3). signature on the signed data are valid
 * */
bool valid_chunk_signature (std::string ncid_sign, std::string publisherName, std::string contentName, std::vector<uint8_t>& data)
{
	//valid the NCID header
	struct stat info;
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
        std::string content_dir = homepath + CHUNKS_DIR;
        std::string path = content_dir + ncid_sign;
	size_t pos_ncid = ncid_sign.find("NCID:");

        if (pos_ncid != std::string::npos) {
		size_t post_sign = ncid_sign.find("::");
		std::string ncid_located = ncid_sign.substr(0, post_sign);
		std::string datahex_located = ncid_sign.substr(post_sign+2);
		Publisher publisher(publisherName);

		//1. receiver could get contentName
                std::string sURI = publisher.content_URI(contentName);

		//2.readin signature binary buffer
		std::string signbin_dir = homepath + SIGNATURE_BIN;
        	std::string signbin_name = signbin_dir + datahex_located;
		
		std::string::size_type  size;
	        std::ifstream infile(signbin_name.c_str(), ifstream::binary);
        	infile.read(reinterpret_cast<char*>(&size), sizeof(std::string::size_type));
        	std::string signature_str;
       		std::vector<char> signbuf(size);
       		infile.read(&signbuf[0], size);
        	signature_str.assign(signbuf.begin(), signbuf.end());

		//clear after done on this signature
		signbuf.clear();

		//Validate1: reciever calcuates NCID from contentName to match the identifier NCID specified in chunkName
		std::string calc_ncid = publisher.ncid(contentName);
		if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
                                cout << "Failed to located the file: " << ncid_sign.c_str() << endl;
                                return false;
                } else {
			//Validate1: reciever calcuates NCID from contentName to match the identifier NCID specified in chunkName
			if( calc_ncid == ncid_located ){
			std::cout << "Validate1).NCID generated from pubkey is equal to the located NCID !!" <<endl;
			
			//Validate2.  Hashvalue of data received  matches sign_  part of ncid_sign, which is contenthash
			if ( valid_chunk_data (ncid_sign.c_str(), data)) {

				std::cout<< "Validate2). NCID content data is valid!!" <<endl;
				
				//3.Receiver has the signed data
				std::string s( reinterpret_cast< char const* >(data.data()), info.st_size);
				std::cout << "The receiver gets the signed data to validation "<<  s.c_str()<< endl;
				std::cout << "data Info size " <<info.st_size<<endl;

				//check validation if passed in a incorrect signature
				//signature_str.assign("This is a invalid signature buf passin");

				//Validate3: Signature valid on contentData
                        	if (publisher.isValidSignature(sURI, s, signature_str)){
                                	 std::cout <<"Validate3). Signature is Valid!! "<<endl;
				 	 return true;
                        	 } else {
                                	std::cout <<"Check validataion signature:  Invalid!! "<<endl;
					return false;
                        	}
			} else {
				std::cout<< "NCID content data didn't match from sender !!" <<endl;
				return false;
			} 
			
		} else {
			std::cout << "Invalid pubkey or contentName !!" <<endl;
			return false;
		}
	    } //end validation 
	} else {
		std::cout << "No need signature validation process for non NCID content" <<endl;
		return false;
	}
}


/**
 * Validate chunk data before load
 * @param sCid - hex string of the content chunk identifier. For NCID, it is formed with hash hexstring of hash of (contentName+ pubkey), and
 *                    hash of chunkdata. eg NCID:0238e29890bc2b6863bc284c9e9587de4b01db18::af39a018730b0acb32a75fd666880ba306efaf62
 *                    for CID content chunkdata eg CID:1ea773d0cfaef702d3dae44a5df63090e931e0d0
 * @param data -chunk data to be validate
 * @return true if the hash value of NCID/CID content data recieved matches the NCID/CID hexstring of chunk data hash
 * */
bool valid_chunk_data (std::string sCid, std::vector<uint8_t>& chunk_data) {
	struct stat info;
	int rc;
	std::string datahex_located;
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
        std::string content_dir = homepath + CHUNKS_DIR;
	std::string cType = "CID";
        cType += ":";
        std::string path = content_dir + sCid;
        size_t pos_ncid = sCid.find("NCID:");
	size_t pos_cid =sCid.find(cType);

        unsigned char digest[SHA_DIGEST_LENGTH];
        char digest_string[SHA_DIGEST_LENGTH*2+1];
	//get the chunk identifer
	if (pos_ncid != std::string::npos) {
                size_t post_sign = sCid.find("::");
                datahex_located = sCid.substr(post_sign+2);
		std::cout<<"NCID chunk identifer " <<datahex_located << endl;
	} else if (pos_cid != std::string::npos) {
		datahex_located = sCid.substr(cType.length());
		std::cout<<"CID chunk identifer " <<datahex_located << endl;
	}
	else {
		std::cout<< "Could not recognized the content chunk identifier" << endl;
		return false;
	}
	//calculate the hash of chunk content located
        if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
        	cout << "Failed to located the file: " << sCid.c_str() << endl;
                return false;
	}
	FILE *f = fopen(path.c_str(), "rb");
	cout << "Check the size of the file : "<< info.st_size<< endl;
	chunk_data.reserve(info.st_size);
	int offset = 0;
	if (!f) {
		cout << "Failed to open the content chunk" << endl;
		return false;
	}
	while (!feof(f)) {
		unsigned char *p = chunk_data.data();
		rc = fread(p + offset, 1, info.st_size, f);
		offset += rc;
	}
	fclose(f);
	
	//pass a tmp check 
	   std::string tmp( reinterpret_cast< char const* >(chunk_data.data()), info.st_size);
          // std::cout << "The receiver gets chunk : "<< tmp.c_str()<< endl;

        /* this block is to test check validation if passed in  a tampered chunkdata -PASS
        tmp.assign("Whatever the content data here to passin test!");
	std::cout <<"tmp tampered data "<<tmp.c_str() <<endl;
	SHA1((const unsigned char *)tmp.c_str(),tmp.size(), digest);
	*/
	
	SHA1(chunk_data.data(),info.st_size, digest);
        hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));
        std::string data_hex = digest_string;
        std::cout << "Receiver get the  datahash hexstring calculated: " << data_hex.c_str()<< endl;

	return (datahex_located == data_hex) ? true : false;
}

/**
 * Step2. Contruct a hex string for each chunked content and write chunks to  
 * content directory defined in content_dir
 * @param buf  - a buffer filled in with chunked data
 * @param byte_count - byteCount of the buffer holding chunked data
 * @return digest_string - a hex string converted from the buffer filled with the SHA1 hash
 * */
std::string write_chunk(const unsigned char *buf, uint32_t byte_count)
{
	unsigned char digest[SHA_DIGEST_LENGTH];
	char digest_string[SHA_DIGEST_LENGTH*2+1];
	std::string homepath = getenv("HOME");
     	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
	std::string content_dir = homepath + CHUNKS_DIR;
	std::string xid_type = XID_TYPE;
	//generate a digesting with the buffer containing a SHA1 hash
	SHA1(buf, byte_count, digest);

	if (mkdir(content_dir.c_str(), 0777) < 0 && errno != EEXIST) {
		std::cout <<"error create the content filepath "<< endl;
		return "";
	}
	hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));
	
	//add type
	std::string hex_with_type = xid_type +":"+digest_string; 
	
	
	//change the trunkname from digest_string to hex_with type

	std::string chunk_name = content_dir + hex_with_type;

	FILE *cf = fopen(chunk_name.c_str(), "wb");
	if (cf == NULL) {
		return "";
	}

	fwrite(buf, 1, byte_count, cf);
	fclose(cf);
	
	return std::string(hex_with_type);
}

/**
 * Call from write_chunk for Named content to  write signature into SIGNATURE_BIN store for client to retrieve
 * @param sign  -  hash of the signed data
 * @param sign_buf -  publiser signature on the signed chunkdata
 * @return 0 if signature is written successfully, -1 otherwise
 **/
int write_signature(std::string sign, std::string sign_buf)
{
	std::string homepath = getenv("HOME");
     	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
	std::string sign_dir = homepath + SIGNATURE_BIN;
	std::string sign_name = sign_dir + sign;

	//std::cout << "Original Signature "<<sign_buf.c_str()<<endl;
	ofstream outfile(sign_name.c_str(), ofstream::binary);
	std::string::size_type fsize= sign_buf.size();
	
	outfile.write(reinterpret_cast<char*>(&fsize), sizeof(std::string::size_type));
	outfile.write(sign_buf.data(), fsize);

	outfile.close();

	//check we upload signation data successfully
	std::string::size_type  size;
	ifstream infile(sign_name.c_str(), ifstream::binary);
	infile.read(reinterpret_cast<char*>(&size), sizeof(std::string::size_type));
	std::string str;
	std::vector<char> buf(size);
	infile.read(&buf[0], size);
	str.assign(buf.begin(), buf.end());
	//std::cout <<"READFILE "<< str.c_str()<<endl;

	if (sign_buf.compare(str)){
		std::cout<<"Signature is loaded successfully" <<endl;
		return -1;
	}

        infile.close();
	return 0;
}

/**
 *To write chunk for named content
 * @param buf:  chunk data to write
 * @param byte_count: chunkdata size
 * @param publisher_Name: data Publiser Name
 * @param content_name: content data
 # @return ncid_sign:  NCID indentifier which is concatination of two hash hexstring: one is hash from contentName and PublicKey; 
 *		       and one is the hexstring of content data hash
 **/
std::string write_chunk(const unsigned char *buf, uint32_t byte_count, std::string publisher_name, std::string content_name) 
{
	std::string homepath = getenv("HOME");
     	#ifdef WORKDIR
        	homepath.assign(WORKDIR);
     	#endif
	std::string content_dir = homepath + CHUNKS_DIR;

	//create a hash of pubkey+contentName
	Publisher publisher(publisher_name);
	
        std::string s_ncid = publisher.ncid(content_name);
	if(s_ncid.size() == 0) 
	{
 		std::cout << "Failed to create NCID for Publisher "<< publisher_name.c_str() << " Content: " << content_name.c_str() <<endl;
        }
	std::cout << "Before signature - 1.Check s_ncid from publisher: "<< s_ncid.c_str()<<endl;

	//test to create a content data hash to use a uniqueContentKey
	unsigned char digest[SHA_DIGEST_LENGTH];
        char digest_string[SHA_DIGEST_LENGTH*2+1];
	SHA1(buf, byte_count, digest);
	hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));
	std::string s_datahex = digest_string;

	std::cout<<"Check contentdata hexstring: " <<s_datahex.c_str() <<" ByteCount: "<<byte_count<<endl;

        if (mkdir(content_dir.c_str(), 0777) < 0 && errno != EEXIST) {
                std::cout <<"error create the content filepath "<< endl;
                return "";
        }

	//sign on the chunkdata
        std::string s_uri = publisher.content_URI(content_name);
        std::string s_buf( reinterpret_cast< char const* >(buf), byte_count);
        std::string signature;
        if(publisher.sign(s_uri, s_buf, signature) == -1) {
                printf("Unable to sign %s\n", s_uri.c_str());
                throw "Failed to sign";
        } else {
                std::cout<<"------------Signature Information --------------"<<endl<<endl;
                std::cout<<"2.Check URI " << s_uri.c_str() <<endl;
                std::cout<<"3.ContentData that signed " <<s_buf.c_str()<<endl;
                std::cout<<"4.Signature " <<signature.c_str()<<endl;
                std::cout<<"------------------------------------------------"<<endl;

                //write the signature into temp binary file for client to retrieve
                int signWritten = write_signature(s_datahex, signature);
                if (signWritten ==0){
                        std::cout <<"Have signature upload onto local to ready for client retrieval" << endl;
                }
        }

	//make unique key on the hash,concatinate the contentdata hashstring
	std::string path_spliter{"::"};
	std::string ncid_sign = s_ncid + path_spliter + s_datahex;
	std::cout <<"6.Check chunk path: " << ncid_sign.c_str() <<endl;
        std::string chunk_name = content_dir + ncid_sign  ;
	
	//write down chunk onto local
        FILE *cf = fopen(chunk_name.c_str(), "wb");
        if (cf == NULL) {
                return "";
        }

        fwrite(buf, 1, byte_count, cf);
        fclose(cf);

        return ncid_sign;
}

/**
 * STEP1. Chunk the file by chunk_size and locate a memory to hold the buffer
 * @param filename:  Readin filesource
 * @param chunk_size: predefined size of per chunk
 * @return CID_LIST_T list of hex strings of the chunked packets
**/
cid_list_t make_chunks(std::string filename, uint32_t chunk_size)
{
	struct stat fs;
	cid_list_t cids;

	if (stat(filename.c_str(), &fs) != 0) {
		return cids;
	}

	FILE *f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		return cids;
	}

	unsigned count = fs.st_size / chunk_size;
	if (fs.st_size % chunk_size) {
		count ++;
	}

	unsigned char *buf = (unsigned char *)malloc(chunk_size);
	if (!buf) {
		fclose(f);
		return cids;
	}

	unsigned byte_count;
	std::string cid;

	//Handle to check if that's the named content 
	// test content file is created under: {xia-core root directory}/tmpContents/
	// FileName format: CNN:2021:12:3:world:News.pdf
	
	// First retrieve the Publisher and Content name eg. CNN:2021:12:3:world:News.pdf
	size_t found_p = filename.find(':');
  	if (found_p!=std::string::npos) {
        	std::string publisher_path = filename.substr(0, found_p);
		std::size_t found = publisher_path.find_last_of("/\\");
		std::string publisher_name = publisher_path.substr(found+1, found_p);
        	std::string content_name = filename.substr(found_p + 1);

		while (!feof(f)) {
			if ((byte_count = fread(buf, sizeof(unsigned char), chunk_size, f)) > 0) {
				if ((cid = write_chunk(buf, byte_count, publisher_name, content_name)) == "") {
					fclose(f);
					cids.clear();
					return cids;
					}
				//add in concatination: ncid +"::"+ signature
				std::cout << "HERE check the NCID "<< cid.c_str()<<endl;
				cids.emplace_back(cid);
				}
			}
	      }	else {
			while (!feof(f)) {
                        if ((byte_count = fread(buf, sizeof(unsigned char), chunk_size, f)) > 0) {
                                if ((cid = write_chunk(buf, byte_count)) == "") {
                                        fclose(f);
                                        cids.clear();
                                        return cids;
                                	}
                                cids.emplace_back(cid);
                        	}
			}
	      }
	free(buf);
	fclose(f);
	return cids;
}

//Step1) Chunkbuffer and call write_chunk to store chunked content into localdisk with path/hashdata as name
cid_list_t put(const char *buffer, uint32_t size, uint32_t chunk_size, uint32_t ttl)
{
	cid_list_t cids;
	std::string cid;

	uint32_t num_chunks = size / chunk_size;
	if (size % chunk_size) {
		num_chunks++;
	}

	const unsigned char *p = (const unsigned char *)buffer;
	uint32_t bytes_remaining = size;
	for (uint32_t i = 0; i < num_chunks; ++i) {

		uint32_t count = (bytes_remaining < chunk_size) ? bytes_remaining : chunk_size;
		if ((cid = write_chunk(p, count)) == "") {
			cids.clear();
			return cids;
		}
		cids.emplace_back(cid);
		p += chunk_size;
		bytes_remaining -= chunk_size;
	}
//	post_cids(cids, ttl);
	return cids;
}

/**
 * Helper function
 * Retrieve the chunked hex strings from cids vector
 */
void print_chunklst (const vector<string>& cid_list_t)
{
	for (int i=0; i<cid_list_t.size(); i++) {
		cout << cid_list_t[i] << endl;
	}
}

/**
 * Retrieve list of hex strings of chunking content data .For CID, that
 * is the ChunkCID, for NCID format NCID:0238e29890bc2b6863bc284c9e9587de4b01db18::af39a018730b0acb32a75fd666880ba306e
 * that will be the NCID: with the second hexsting after :: symbol 
 */
vector <string> contentChunkIDs(std::string file){
	std::cout<<"Build list of  chunkXIDs from the content ----"<<std::endl;
	vector <string> xidLst;
	std::string NCIDtype("NCID:");
        cid_list_t chunkIDs = chunk_file(file, TEST_CHUNK_SIZE, default_ttl);
	for (int i=0; i<chunkIDs.size(); i++) {
                std::size_t bFound = chunkIDs[i].find(NCIDtype);
                std::string tmp_xid = (bFound != std::string::npos) ?  NCIDtype + chunkIDs[i].substr(chunkIDs[i].find("::")+2) : chunkIDs[i];
		xidLst.emplace_back(tmp_xid);
	}
        return xidLst;
}


/**
 * Add the cid list to hash table
 * load the initial hashtable and add more items
 **/
chunkhash_table* initHashtable (const vector<string>& cid_list_t){
	chunkhash_table* Hashtmp = create_table(TABLE_SIZE);
	for (int i=0; i<cid_list_t.size(); i++){
		
		std::string tmpName = cid_list_t[i];
		std::string homepath = getenv("HOME");
     		#ifdef WORKDIR
        		homepath.assign(WORKDIR);
     		#endif
		std::string tmpPath = homepath + CHUNKS_DIR + tmpName;

 		char a1[(cid_list_t[i]).size() + 1];
        	strcpy(a1, (cid_list_t[i]).c_str());

          	char a2[tmpPath.size() + 1];
        	strcpy(a2, tmpPath.c_str());

		std::cout << "Add chunk item to hashtable"<< cid_list_t[i].c_str()<<endl;
		AddItem(Hashtmp, a1, a2);

	}
	return Hashtmp;

}


/**
 * STEP0: 
 * @param filename -Readin fileName to process
 * @param chunk_size - Size of per chunk defined
 * @param ttl - time to keep chunks
 * */
cid_list_t chunk_file(std::string filename, uint32_t chunk_size, uint32_t ttl)
{
	cid_list_t cids;
	std::cout <<"Call from chunkapi to make chunks"<<endl;
	cids = make_chunks(filename, chunk_size);

//	post_cids(cids, ttl);
	return cids;
}


/**
 * Retrieve the chunks mapping from the FileSystem
 * @param path - directory of the chunked file storage
 * @returns chunkmappings
 *    chunkid   -hex string of the chunk, used as mapping key
 *    filepath  -location to retrieve the chunked packet
 *    filetype  -type of the chunked packet
 *    filesize  -size of the chunked packet
 **/
std::map <std::string, chunkMeta> get_mapOfchunks (std::string path )
{
  map<std::string, chunkMeta> tmpMap;
  struct stat st;
  std::string homepath = getenv("HOME");
  #ifdef WORKDIR
        homepath.assign(WORKDIR);
  #endif
  std::string content_dir = homepath + CHUNKS_DIR;
  struct dirent* de;
  DIR* dp= opendir( path.c_str());
  chunkMeta cmObj;
  
  while ((de = readdir(dp)) != NULL)
  {
      if( strcmp(de->d_name,".") != 0 &&  strcmp(de->d_name, "..") !=0 
		      && stat(de->d_name, &st) != 0)
 	{
        	cmObj.chunkid = de->d_name;
		cmObj.fpath = content_dir + de->d_name;
		cmObj.fsize = st.st_size;

        	tmpMap.insert( std::make_pair( de->d_name, cmObj) );
      	}
  }
  closedir( dp );
  
 for (auto itr = tmpMap.begin(); itr != tmpMap.end(); ++itr)
  	{
	std::cout << "f_index " << itr->first << "  f_path  " <<itr->second.fpath <<endl;
  	}
  return tmpMap;
}
