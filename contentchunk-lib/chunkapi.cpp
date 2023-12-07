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

#include "localconfig.hpp"
#include "headers/ncid_header.h"
#include "dagaddr.hpp"
#include "chunkhash.h"
#include <cmath>

//#define WORKDIR "/home/testpath"  // default WORKDIR is user's home directory
#define CONFFILE "./conf/local.conf"
#define CHUNKS_DIR "/picoquic/tmpChunks/"
#define SIGNATURE_BIN "/picoquic/tmpSignatureBin/"
const uint32_t default_chunk_size = 1024 * 1024;
const uint32_t default_ttl = 0;
#define TEST_CHUNK_SIZE 300
#define CONTENT_STORE "CONTENT_STORE"
#define KEY_DIR  "KEY_DIR"
#define XID_TYPE  "CID"
#define WORKDIR "WORKDIR"

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
 * Check if the public key exists in the path
 * @param filename
 * return true if public key file is accessible
 */
bool pubkfile_exists(std::string path)
{
        struct stat statbuf;

        if( stat(path.c_str(), &statbuf) ==0) {
                return true;
        } else{
                std::cout << "ERROR: failed to access pubkey" << std::endl;
                return false;
        }
}


/**
 * @content receiver accesses pubkey
 * @param publisher key filepath
 * return public key string if file is accessible
 */
std::string get_pubkey(std::string keypath)
{
        char pubkeybuf[MAX_PUBKEY_SIZE];
        uint16_t pubkeylen = MAX_PUBKEY_SIZE;
        memset(pubkeybuf, 0, pubkeylen);

        // If the pubkey is not available, try getting it
        if(!pubkfile_exists(keypath)) {
		printf("ERROR: failed to access pubkey file");
                        return "";
        }
        // Find the pubkey file in the PublisherKey's credential directory
        if(xs_readPubkeyFile(keypath.c_str(), pubkeybuf, &pubkeylen) == -1) {
                printf("PublisherKey::pubkey() cannot read key from %s\n",
                                keypath.c_str());
                return "";
        }
        std::string pubkeystr(pubkeybuf, pubkeylen);
        return pubkeystr;
}

/**
 * @content publisher key accesses path
 @param publisherName
 @param type of the key to access, set pubkey path to be default
 * return publisher's keyPath
 */
std::string get_keypath(std::string publisherName, int is_privkey)
{
        auto conf = LocalConfig(CONFFILE);
        std::string keydir = conf.get(KEY_DIR);
        std::string homepath = getenv("HOME");
        #ifdef WORKDIR
                homepath.assign(conf.get(WORKDIR));
        #endif
        std::string publisher_keydir = homepath +  keydir + publisherName;

        std::string keyfilepath = (is_privkey == 1) ? publisher_keydir + "/" + publisherName + ".priv"
                                                   : publisher_keydir + "/" + publisherName + ".pub";
        return keyfilepath;
}

/**
 * @receiver verify the digest of contentData associated to URI with public key access
 @param publisherName
 @param contentName and URI from receiver's content request
 @param content signed contentData
 @param signature to validate for the digest
 * return ture if signature is valid, otherwise false
 */

bool isValidSign(std::string publisherName,
		std::string content_URI,
                const std::string &content,
                const std::string &signature)
{
	std::string pubkeyfile = get_keypath(publisherName, 0);
        std::string data = content_URI + content;

        // Get the digest of data
        uint8_t digest[SHA_DIGEST_LENGTH];
        xs_getSHA1Hash((const unsigned char *)data.c_str(), data.size(),
                        digest, sizeof(digest));

	std::string str_digest;
	str_digest.assign((const char*)digest, (size_t)sizeof(digest));
	if(xs_isValidDigestSignature(pubkeyfile.c_str(),
                                (const unsigned char *)str_digest.c_str(), str_digest.size(),
                                (unsigned char *)signature.c_str(), signature.size()) != 1) {
                std::cout << "ERROR invalid signature" << std::endl;
                return false;
        }
        return true;
}


/* NCID content: unpack signature from chunkdata
 * @param xid   - content identfier
 * @param process type - application operation type, eg. GET, PUT
 * @param data  - data received 
 * @return  signature and signed data
 * */

std::pair<string, vector<uint8_t> > get_data_signature(std::string &xid, uint8_t* bytes,  size_t length, int sign_offset, string processType )
{
	std::string s_signpart;
	std::vector<uint8_t> data_part;
	std::pair<string, vector<uint8_t> > xid_pair;
		int data_offset = (processType.compare("GET")==0) ? 0 : xid.length();
		if (xid.find("NCID:") != string::npos)
		{//NCID signature part
                char signpart[sign_offset+1];
                memcpy(signpart, bytes+data_offset, sign_offset);
                signpart[sign_offset]=0;//last character
                s_signpart.assign(signpart, signpart+sign_offset);
                //std::cout<<"Signature part: "<<s_signpart.c_str()<<endl;
		}
                //data part
                char datapart[length-(data_offset +sign_offset)+1];
                memcpy(datapart, bytes+data_offset+sign_offset, length-sign_offset-data_offset); 
                datapart[length-(sign_offset+data_offset)+1] = 0; //set the last position datapart  to null to terminate
                string sdatapart(datapart);
                //std::cout<<"Check data part: " <<sdatapart.c_str()<<endl;
		data_part.insert(data_part.begin(), datapart, datapart + sizeof(datapart));
		
		xid_pair.first=s_signpart;
                xid_pair.second=data_part;
		
		return xid_pair;
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
		 auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
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

std::vector<uint8_t> get_chunkdata(std::string cid,string processType, size_t cSize)
{
    std::vector<uint8_t> cData;

    //Check to see if CID content is available on xcache local:
     std::string homepath = getenv("HOME");
     #ifdef WORKDIR
     	 auto confile = LocalConfig(CONFFILE);
     	 homepath.assign(confile.get(WORKDIR));
     #endif
     std::string CID_path = homepath + CHUNKS_DIR + cid;

      std::ifstream tmp_fin(CID_path.c_str(), std::ios::in | std::ios::binary);
     if (tmp_fin.good()){ //check if the file is local in the path

             //start stream to prepare to sent to requester
             tmp_fin.seekg(0, std::ios::end); //take the lenghth of the file
             //size_t f_size = tmp_fin.tellg();
	     cSize =tmp_fin.tellg();
             tmp_fin.seekg(0, std::ios::beg);

             char dataCID[cSize];
             tmp_fin.read(dataCID, sizeof dataCID);
             tmp_fin.close();

             printf("Reading  %ld bytes of data \n", sizeof(dataCID));
             cData.insert(cData.begin(), dataCID, dataCID + sizeof(dataCID));
   	     //cout<<"Data retrieved from chunkstorage :" <<cData.data()<<endl;

         //For NCID, append the signature also
	 std::string sType("NCID:");
         if (cid.find("NCID:") != std::string::npos) {
		 if(processType.compare("PUT")!=0) {
			 //on contentProvider: signature of chunkdata should exist if chunkdata is existing
			 printf("NCID GET DATA with Signature!!!\n");
		 }
		 // requester has the chunkdata signature available
                	std::string datahex_loc = cid.substr(sType.length());

                	//read the signature from storage
                	std::string sign_dir = homepath + SIGNATURE_BIN;
                	std::string sign_name = sign_dir + datahex_loc;

                	std::string::size_type  sig_size=0;
                	ifstream sig_f(sign_name.c_str(), ifstream::binary);
                	sig_f.read(reinterpret_cast<char*>(&sig_size), sizeof(sig_size)); //read size
                	std::string sig_str;
                	std::vector<char> sig_buf(sig_size);
                	sig_f.read(&sig_buf[0], sig_size);
                	sig_str.assign(sig_buf.begin(), sig_buf.end());

                	//now append the signature data to chunk
                	cData.insert(cData.begin(), sig_str.data(), sig_str.data()+sig_str.length());
                	//std::cout <<"READFILE after appending signature "<< cData.data()<<endl;
        	} 

     } else {
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
		auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
        #endif
        std::string content_dir = homepath + CHUNKS_DIR;
        std::string path = content_dir + cid;

        std::vector<uint8_t> tmp;

        if (stat(path.c_str(), &info) < 0 || info.st_size == 0) {
                cout << "Failed to located the file: " << cid.c_str() << endl;
                auto chunkInfo =std::make_tuple(path,tmp, 0);
                return chunkInfo;

        } else {
                cout << "Start fetching data from "<< path.c_str() << " of size " << info.st_size << endl;

                FILE *f = fopen(path.c_str(), "rb");

                data.reserve(info.st_size);
                int offset = 0;

                if (!f) {
                        auto chunkInfo =std::make_tuple(path,tmp, 0);
                        return chunkInfo;
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
bool valid_chunk_signature (std::string ncid_sign, std::string &signature, size_t dSize, std::string datahex, std::vector<uint8_t>& data)
{
	auto conf = LocalConfig(CONFFILE);
	std::string content_fname;
        content_fname = conf.get(CONTENT_STORE);
	struct stat info;
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
		 homepath.assign(conf.get(WORKDIR));
        #endif
	std::string content_dir = homepath + CHUNKS_DIR;	
	size_t post_ncid = ncid_sign.find("NCID:");
	if (post_ncid != std::string::npos) {

	 //Validation FirstPart: Signature
		//Readin publisherName from '/picoquic/tmpContents/CNN:2022:01:19:world:covidnewsupdate.txt'
		size_t found_p = content_fname.find(':');
       		if (found_p != std::string::npos) {
			std::string publish_path = content_fname.substr(0, found_p);
                	std::size_t found = publish_path.find_last_of("/\\");
                	std::string publisherName = publish_path.substr(found+1, found_p);
                	std::string contentName = content_fname.substr(found_p + 1);
		//1. get same hash(content_URI +data)
			Publisher publisher(publisherName);
			std::string content_uri = publisher.content_URI(contentName);
			//std::cout<<"1. Verify URI :"<<content_uri.c_str()<<endl;

		//get digest of chunkdata and uri
			std::string s( reinterpret_cast< char const* >(data.data()), dSize);
			//printf("data size: %zu\n", dSize);
			//std::cout<<"2. Verify contentData: "<<s.c_str()<<endl;

			std::string data =content_uri + s;
			uint8_t digest[SHA_DIGEST_LENGTH];
        		xs_getSHA1Hash((const unsigned char *)data.c_str(), data.size(),
                        digest, sizeof(digest));

		//3. receiver accesses pubkey dir
			 std::string pubkeyfile = get_keypath(publisherName, 0);
                  	 std::string pubkeystr = get_pubkey(pubkeyfile);
		//4. get signature string
			//std::cout<<"3. Signature to verify : "<<signature.c_str()<<endl;
		//	signature.assign("Whatever contaminated signature to passin test!");
		//5. verify signature
		        if (isValidSign(publisherName, content_uri, s, signature)){
                                        printf("Valid Sign!!!\n");
		//6. verify NCID
			 std::string calc_name_data = content_uri + datahex;
			 //now calc the NCID using the same algrithom from publisher
			 std::string calc_ncid_data = calc_name_data + pubkeystr;

        		 char calc_ncidhex[XIA_SHA_DIGEST_STR_LEN];
        		 int calc_ncidlen = XIA_SHA_DIGEST_STR_LEN;
        		 xs_getSHA1HexDigest((const unsigned char *)calc_ncid_data.c_str(),
                         calc_ncid_data.size(), calc_ncidhex, calc_ncidlen);
        		 assert(strlen(calc_ncidhex) == XIA_SHA_DIGEST_STR_LEN - 1);
        		 std::string calc_ncidstr(calc_ncidhex);

			 std::cout << "Calcs_ncid : "<< calc_ncidstr.c_str()<<endl;
			 if( calc_ncidstr == ncid_sign.substr(ncid_sign.find(":") +1) ){
				std::cout<< "NCID header is valid!!" <<endl;
				return true;
			} else {
				std::cout << "Invalid NCID header received !!" <<endl;
				return false;}

	    		} else {
                                printf("Invalide Sign\n");
				return false;}		 
		} else {
                        printf("ERROR: incorrect NCID contentName format readin!!\n");
                        return false;
                }
	} else {
		std::cout << "Incorrect NCID header format" <<endl;
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
		auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
     	#endif
        std::string content_dir = homepath + CHUNKS_DIR;
        std::string path = content_dir + sCid;
        size_t pos_ncid = sCid.find("NCID:");

        unsigned char digest[SHA_DIGEST_LENGTH];
        char digest_string[SHA_DIGEST_LENGTH*2+1];
	//get the chunk identifer (N)CID
	
	std::string cType = (pos_ncid != std::string::npos) ? "NCID" : "CID";
	cType += ":";

	datahex_located = sCid.substr(cType.length());
	std::cout<<"XID chunk identifer " <<datahex_located << endl;

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
		auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
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
		 auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
        #endif 
        std::string sign_dir = homepath + SIGNATURE_BIN;
        std::string sign_name = sign_dir + sign;
	
	//write buffer
        //std::cout << "Original Signature "<<sign_buf.data()<<" length: "<<sign_buf.length()<<endl;
        ofstream outfile(sign_name.c_str(), ofstream::binary);
 
	//write buffer to file
        std::string::size_type fsize= sign_buf.size(); //get the size to file
        outfile.write(reinterpret_cast<char*>(&fsize), sizeof(std::string::size_type));
        outfile.write(sign_buf.data(), fsize); //write data
        outfile.close();
        
        //check we upload signation data we just stored  successfully
        std::string::size_type  size=0; 
        ifstream infile(sign_name.c_str(), ifstream::binary);
        infile.read(reinterpret_cast<char*>(&size), sizeof(size)); //read size
        std::string str;
        std::vector<char> buf(size);
        infile.read(&buf[0], size);
        str.assign(buf.begin(), buf.end());
        //std::cout <<"READFILE "<< str.data()<<endl;
        //printf("Check the signature comparison: %d \n", sign_buf.compare(str));
	
        if (sign_buf.compare(str)==0){
                std::cout<<"Signature is loaded successfully" <<endl;
        } else{
                std::cout<<"Signature is not matched with original one" <<endl;
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
		 auto confile = LocalConfig(CONFFILE);
		 homepath.assign(confile.get(WORKDIR));
     	#endif
	std::string content_dir = homepath + CHUNKS_DIR;
	std::string sType("NCID:");

	//create a hash of pubkey+contentName
	Publisher publisher(publisher_name);
	
	//create a content data hash to use a uniqueContentKey
	unsigned char digest[SHA_DIGEST_LENGTH];
        char digest_string[SHA_DIGEST_LENGTH*2+1];
	SHA1(buf, byte_count, digest);
	hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));
	std::string s_datahex = digest_string;

	std::cout<<"Content data hexstring: " <<s_datahex.c_str() <<" ByteCount: "<<byte_count<<endl;

	///construct unique new_ncid from SHA1(pubkey+ publisherName +content_name_data)
	std::string content_name_data = content_name + s_datahex;
	std::string s_ncid = publisher.ncid(content_name_data);
        if(s_ncid.size() == 0)
        {
                std::cout << "Failed to create NCID for Publisher "<< publisher_name.c_str() << " Content: " << content_name.c_str() <<endl;
        }
        std::cout << "1.s_ncid from publisher: "<< s_ncid.c_str()<<endl;

        if (mkdir(content_dir.c_str(), 0777) < 0 && errno != EEXIST) {
                std::cout <<"error create the content filepath "<< endl;
                return "";
        }

	//step2. sign on the given chunkdata associated with content URI
	std::string s_uri = publisher.content_URI(content_name);
        std::string s_buf( reinterpret_cast< char const* >(buf), byte_count);
        std::string signature;
        if(publisher.sign(s_uri, s_buf, signature) == -1) {
                printf("Unable to sign %s\n", s_uri.c_str());
                throw "Failed to sign";
        } else {
              //  std::cout<<"------------Signature Information --------------"<<endl<<endl;
              //  std::cout<<"2.Check URI " << s_uri.c_str() <<endl;
              //  std::cout<<"3.ContentData that signed " <<s_buf.c_str()<<endl;
              // std::cout<<"4.Signature " <<signature.c_str()<<endl;
              //  std::cout<<"------------------------------------------------"<<endl;

                //write the signature into temp binary file client to retrieve
                size_t sign_pos = (s_ncid.find(sType) != std::string::npos) ?  sType.length(): 5;
                int signWritten = write_signature(s_ncid.substr(sign_pos), signature);
                if (signWritten ==0){
                        std::cout <<"Have signature upload onto local to ready for client retrieval" << endl;
                }
        }
	//write down chunk onto local
        std::string chunk_name = content_dir + s_ncid ;
        FILE *cf = fopen(chunk_name.c_str(), "wb");
        if (cf == NULL) {
                return "";
        }
        fwrite(buf, 1, byte_count, cf);
        fclose(cf);

        return s_ncid;
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

if (stat(filename.c_str(), &fs) == 0) { //if file is existing

	FILE *f = fopen(filename.c_str(), "rb");
	if (f == NULL) {
		printf( "File could not be opened to retrieve your data from it.\n" );
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
			if ((byte_count = fread(buf, sizeof(unsigned char), chunk_size-128, f)) > 0) {
				if ((cid = write_chunk(buf, byte_count, publisher_name, content_name)) == "") {
					fclose(f);
					cids.clear();
					return cids;
					}
				cids.emplace_back(cid);
				}
			}
	} else {
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

	} else {
		cout<< "Error: Failed to locate content file "<< filename.c_str()<<endl;
	}
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
        cid_list_t chunkIDs = chunk_file(file, TEST_CHUNK_SIZE, default_ttl);
	for (int i=0; i<chunkIDs.size(); i++) {
		std::string tmp_xid = chunkIDs[i]; //Do I need the first part of string
		xidLst.emplace_back(tmp_xid);
	}
        return xidLst;
}


/**
 * Add the cid list to hash table
 * load the initial hashtable and add more items
 **/
chunkhash_table* initHashtable (chunkhash_table* Hashtmp, const vector<string>& cid_list_t){
	for (int i=0; i<cid_list_t.size(); i++){
		
		std::string tmpName = cid_list_t[i];
		std::string homepath = getenv("HOME");
     		#ifdef WORKDIR
			 auto confile = LocalConfig(CONFFILE);
			 homepath.assign(confile.get(WORKDIR));
     		#endif
		std::string tmpPath = homepath + CHUNKS_DIR + tmpName;

 		char a1[(cid_list_t[i]).size() + 1];
        	strcpy(a1, (cid_list_t[i]).c_str());

          	char a2[tmpPath.size() + 1];
        	strcpy(a2, tmpPath.c_str());

		std::cout << "Add chunk item to hashtable"<< cid_list_t[i].c_str()<<endl;
		AddItem(Hashtmp, a1, a2);

	}
	printTable(Hashtmp);
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
  	 auto confile = LocalConfig(CONFFILE);
  	 homepath.assign(confile.get(WORKDIR));
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
