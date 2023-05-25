
/**
 * Construct chunkitem hashtable header
 **/
#ifndef CHUNKHASH_H
#define CHUNKHASH_H
#include <iostream>
#include <sys/types.h>
#include <string>
#include <cstdlib>
#include <pthread.h>

using namespace std;
#define TABLE_SIZE 5000009

		static const int tableSize=TABLE_SIZE;

		struct chunkhash_item {
    			char* cname;
			char* cpath;
			chunkhash_item *next; //handle collsion
		} ;

		//contains array of pointers to chunkitems
		typedef struct chunkhash_table {
    		chunkhash_item** items;
    		int size;
		int count;
		pthread_mutex_t mtxlock;
		} chunkhash_table;

		chunkhash_table* create_table(int tableSize);
		unsigned int cHash(char* key);

		static char* LookupChunk(chunkhash_table* table, char* cname);
                static void printChunkitems(chunkhash_table* table, unsigned int index);

		void AddItem(chunkhash_table* table, char* cname, char* cpath);
		void RemoveItem(chunkhash_table* table, char* cname);
		static chunkhash_item* create_item(char* cname, char* cpath);
		void releaseItem(chunkhash_item* item);
		void releaseTable(chunkhash_table* table);

		int print_lookup(chunkhash_table* table, char* cname);
		void printTable(chunkhash_table* table);
		
#endif /* CHUNKHASH_H */
