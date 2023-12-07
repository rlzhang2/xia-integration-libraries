#include "../xia-api-lib/xiaapi.hpp"
#define CONFFILE "./conf/local.conf"

#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <cstdio>
#include "cid_header.h"
#include <openssl/pem.h>
#include "Xsecurity.h"
#include "chunkapi.h"
#include "get_putChunkapi.h"
#include <fstream>
#include <iostream>
#include <string.h>
#include <stdlib.h>

#include "headers/ncid_header.h"
//#define WORKDIR "/home/testpath"  //default is user's home directory
#define WORKDIR "WORKDIR"
#define CHUNKS_RECV_DIR "CHUNKS_RECV_DIR"

using namespace std;

/* Client(requestor) add cids content stream to connection
 * @param 
 *        connecton: current quic connection instance
 *        context: context assoicated to the quic connection
 *        xid: content identifier
 *        counter: counter of the requested xids to get
 * @return: void
 * */
void put_chunk(picoquic_cnx_t* connection,
                struct callback_context_t* context,std::string process_type, vector <string> xid_lst)
{
        //First add the context->xid
        printf("Starting a stream on XID\n");

        uint64_t stream_id = 0;
        context->stream_open = 1;
        context->connected = 1;
        //int checkend =0;
	std::string cid_data("");
	std::vector<uint8_t> putChunkData;

	if(process_type.compare("GET")==0){
	 for (int i=0; i<xid_lst.size(); i++){
                        std::cout<<"XID: "<< xid_lst[i].c_str()<<endl;
                        context->xid.push_back(xid_lst[i]); //assign XIDs to context
			cid_data = cid_data.append(xid_lst[i]);
	 		}
		//get all CID data
		char data[cid_data.length()];
                strcpy(data, cid_data.c_str());

        	printf("Sending CIDData length: %ld Data length: %ld CID string %s \n", cid_data.length(), sizeof(data), data);
		if(picoquic_add_to_stream(connection,
                                stream_id, // Any arbitrary stream ID client picks
                                (uint8_t*)data, sizeof(data), // data to be sent
                               0)) { // finished; would be 0 if interacting more with server
                	printf("ERROR: sending CID string to stream\n");
                }
	}

        //if the process is for PUT request, then we will also send cid chunk data
        if(process_type.compare("PUT")==0) {
		printf("%" PRIx64 ": \n", picoquic_val64_connection_id(picoquic_get_logging_cnxid(connection)));
		for (int i=0; i<xid_lst.size(); i++){
                        std::cout<<"XID: "<< xid_lst[i].c_str() <<" length: "<< xid_lst[i].length()<<endl;
                        context->xid.push_back(xid_lst[i]); //assign XIDs to context
                        cid_data = cid_data.append(xid_lst[i]);
                        
                        //get the current XID
                        char tmpdata[strlen(xid_lst[i].c_str())];
                        strcpy(tmpdata, xid_lst[i].c_str());

			//get current XID data
			std::vector<uint8_t> tmpChunkData;
                	tmpChunkData = get_chunkdata(xid_lst[i], process_type, TEST_CHUNK_SIZE);
         		printf("Now Calculated  %ld XID Data!!! \n", tmpChunkData.size());

                //Prefix CID data to the chunk content data, so tmpChunkData is completed cid putData
                tmpChunkData.insert(tmpChunkData.begin(), tmpdata, tmpdata+sizeof(tmpdata));
		
		if(picoquic_add_to_stream(connection,
                                stream_id, // Any arbitrary stream ID client picks
				tmpChunkData.data() , tmpChunkData.size(), // data to be sent
                               0)) { // finished; would be 0 if interacting more with server
                			printf("ERROR: sending CID string to stream\n");
				}
                }
	}
}


/* Client(requestor) load chunk data received to local file storage
 * @param 
 *        connecton: current quic connection instance
 *        context: context assoicated to the quic connection
 *        bytes: data received on context
 *        length: length of data received
 * @return: int 0 if successful otherwise -1
 * */
int store_chunk(picoquic_cnx_t* cnx, struct callback_context_t* context,
        uint8_t* bytes, size_t length, string xid_requested, string process_type) {
        std::cout<<"--------function: "<<__FUNCTION__<<"------"<<endl;
                std::string path;
                std::string homepath = getenv("HOME");
		auto conf = LocalConfig(CONFFILE);
                #ifdef WORKDIR
                        homepath.assign(conf.get(WORKDIR));
                #endif
        	std::string recv_dir = conf.get(CHUNKS_RECV_DIR);
                std::string tmp_fs = homepath + recv_dir;
                size_t found;
                int type_offset=0;
		int sign_offset=  (xid_requested.find("NCID:") != string::npos) ? 128 : 0; //NCID:RSA signature size due to 1024 bit RSA key used
                FILE *cf;
		bool b_StoreData = new bool();  //default to false

		std::pair<string, vector<uint8_t> > xid_tmp;

                //Validate data received: calculate the SHA1 of data received, then match it with the requested CID
                unsigned char digest[SHA_DIGEST_LENGTH];
                char digest_string[SHA_DIGEST_LENGTH*2+1];

                //for PUT: separate the CID with data, also error if total buf length is less than  XID  length
                if ( process_type.compare("PUT")==0 ){
			//fixed length on xid type 40byte, NCID has signatured attached
			type_offset = (xid_requested.find("NCID:") != string::npos) ? xid_requested.length()+sign_offset-1 : xid_requested.length()-1;

			if (length > type_offset +1 ) {//since both CID and NCID are defined as a fixed length
				xid_tmp =get_data_signature(xid_requested, bytes, length, sign_offset, process_type);
				SHA1((get<1>(xid_tmp)).data(),length-(type_offset+1), digest);
			} else {
				printf("Invalid NCID data format on  put operation!!"); //incorrect ncid format to put
                        	return -1;
			}
                } else {//GET
			//for NCID: data sparate signature and chunkdata
			 if (xid_requested.find("NCID:") != string::npos){
				xid_tmp =get_data_signature(xid_requested, bytes, length, sign_offset, process_type);
                                SHA1((get<1>(xid_tmp)).data(),length-sign_offset, digest);
			 } else {
                        	SHA1(bytes,length, digest);
			 }
                }

                hex_digest(digest, sizeof(digest), digest_string, sizeof(digest_string));
                std::string data_hex = digest_string;
                std::cout << "Hex  calculated from received data: " << data_hex.c_str()<< endl;

		//check the xid format
		if (!(xid_requested.find(":") == string::npos)) {
			found = xid_requested.find_last_of(":");
                	std::string id_located_upd = xid_requested.substr(found+1);
                	std::string type_located =  xid_requested.substr(0,found+1);

               		//valid NCID content request
               		if (xid_requested.find("NCID:") != string::npos) {

				b_StoreData = ( process_type.compare("PUT")==0) ?  
			     		valid_chunk_signature (xid_requested, get<0>(xid_tmp), 
						length-(type_offset+1), data_hex, get<1>(xid_tmp))
					: valid_chunk_signature (xid_requested, get<0>(xid_tmp), 
                                                length-sign_offset, data_hex, get<1>(xid_tmp));
			//valid data only for CID
			} else if ((xid_requested.rfind("CID:") != string::npos)){
                        	//if matched, store data in the server file storage
                        	b_StoreData = (strcmp(data_hex.c_str(), id_located_upd.c_str()) == 0) ? true :false;
			} else {
		        	printf("Error: Invalid XID type received!!"); 
		 		return -1;	
			}

			//now store chunk
			if (b_StoreData) {
                                //path = tmp_fs + type_located  + data_hex;
				path = tmp_fs + xid_requested;
                                printf("Valid Content received!! %s\n", path.c_str());

                                //load the chunk on local file storage, create path if not existing
                                 if (mkdir(tmp_fs.c_str(), 0777) < 0 && errno != EEXIST) {
                                        std::cout <<"ERROR: create the chunk received filepath "<< endl;
                                        return -1;
                                         }
                                 //store content only if not exists
                                 cf = fopen(path.c_str(), "rb");
                                 if (cf == NULL) {
                                        cf = fopen(path.c_str(), "wb");
                                        if (cf == NULL) {
                                                return -1;
                                                }

                                        //For PUT: only the chunk data need to save into storage
                                        if(process_type.compare("PUT")==0){
                                                fwrite((get<1>(xid_tmp)).data(), 1, length-(type_offset+1), cf);
                                        } else {
						 if (xid_requested.find("NCID:") != string::npos){
					             fwrite((get<1>(xid_tmp)).data(), 1, length-sign_offset, cf);
						 } else{
                                                     fwrite(bytes, 1, length, cf);
						 }
                                        }
                                 } else{
                                         printf("content already in storage!!\n");
                                 }
                                fclose(cf);
                                return 0;
             		} //stored
			else {
				printf("Error: Invalid XID content received!!");
				return -1;
			}
	} else {
             	printf("Error: Invalid XID format requested!!");
             	return -1;
              }
}


//PUTProcess Client Callback
static int client_putdata_transfer(picoquic_cnx_t* cnx,
                uint64_t stream_id, uint8_t*bytes, size_t length,
                picoquic_call_back_event_t event, void *callback_context)
{
        std::cout<<"Client PUT Call_back:  client_data_transfer !!!"<<endl;
        std::cout<<" Stream ID: " <<stream_id << "Size of Bytes: "<<sizeof(bytes)<<std::endl;

        struct callback_context_t *context =
                (struct callback_context_t*)callback_context;

        context->last_interaction_time = picoquic_current_time();
	if (!context->xid.empty()){
		printf("Context xid data has assigned!!!\n");
        	printf("Client requested contentID : %s  len: %zu\n", (context->xid[stream_id]).c_str(), length);
	}

        switch(event) {
                case picoquic_callback_ready:
                        printf("Callback: ready\n");
                        break;
                case picoquic_callback_almost_ready:
                        printf("Callback: almost_ready\n");
                        break;
                case picoquic_callback_close:
                        printf("Callback: close\n");
                case picoquic_callback_application_close:
                        printf("Callback: application close\n");
			picoquic_set_callback(cnx, NULL, NULL);//RZ TEST0921
                case picoquic_callback_stateless_reset:
                        printf("Callback: stateless reset\n");
                        context->stream_open = 0;
                        return 0;
                case picoquic_callback_stream_reset:
                        printf("Callback: stream reset\n");
                case picoquic_callback_stop_sending:
                        printf("Callback: stop_sending\n");
                        picoquic_reset_stream(cnx, stream_id, 0);
                        context->stream_open = 0;
                        return 0;
		case picoquic_callback_stream_data:
                        printf("Callback: no event\n");
                        if(length > 0) {
                               char data[length];
                               memcpy(data, (char*)bytes, length);
                               printf("Server sent stream data: %s\n", data);
                               context->received_so_far += length;
                               printf("Check data received from server: %d\n", context->received_so_far);
                        }
                        break;

                case picoquic_callback_stream_fin:
                        printf("Callback: stream finished\n");
                        if(length > 0) {
                                char data[length];
                                memcpy(data, (char*)bytes, length);
                                printf("Server sent: %s\n", data);
                                context->received_so_far += length;

                                printf("Client requested CID : %s\n", (context->xid[stream_id]).c_str());

                        }

                        printf("NOW Check ACK from ServerEnd to PUT :");
                               //pull Client ack response after processing stream data from Client
                                char rdata[length+1];
                                memcpy(rdata, bytes, length);
                                rdata[length] = 0;
                                std::string ClientAck(rdata);
                                cout<<"Server sent response after completed stream: "<< ClientAck.c_str()<<endl;

                                printf("ServerCallback: Client sent %d bytes before ending\n",
                                                context->received_so_far);
                        context->stream_open = 0;
                        printf("Reception completed after %d bytes.\n",
                                        context->received_so_far);
                        printf("Resetting the stream after it finished.\n");
                        picoquic_reset_stream(cnx, stream_id, 0);

                        break;
        };
        return 0;
}


//GetProcess Client CallBack
static int client_data_transfer(picoquic_cnx_t* cnx,
                uint64_t stream_id, uint8_t*bytes, size_t length,
                picoquic_call_back_event_t event, void *callback_context)
{
	std::cout<<"------ GET process "<<__FUNCTION__ <<"  !!!-------"<<endl;
        std::cout<<" Stream ID: " <<stream_id << "Size of Bytes: "<<sizeof(bytes)<<std::endl;
	printf("streaming data length %zu\n", length);

        struct callback_context_t *context =
                (struct callback_context_t*)callback_context;
	std::string process_type ="GET";
	bool b_validate = false;
        context->last_interaction_time = picoquic_current_time();
	if (!context->xid.empty()) { //not the first initial stream
		std::cout<<"Start process individual cid content!! :"<<stream_id<<endl;
		
		//Client initialize streams with odd# onto Server, default stream 0 is the CIDs string
	} else {
		printf("Context xids not assigned yet!!!");
	}
	switch(event) {
                case picoquic_callback_ready:
                        printf("Callback: ready\n");
                        break;
                case picoquic_callback_almost_ready:
                        printf("Callback: almost_ready\n");
                        break;
                case picoquic_callback_close:
                        printf("Callback: close\n");
                case picoquic_callback_application_close:
                        printf("Callback: application close\n");
                case picoquic_callback_stateless_reset:
                        printf("Callback: stateless reset\n");
                        context->stream_open = 0;
			//RZ close connection 
			picoquic_close(cnx, 0);
                        return 0;
                case picoquic_callback_stream_reset:
                        printf("Callback: stream reset\n");
                case picoquic_callback_stop_sending:
                        printf("Callback: stop_sending\n");
                        picoquic_reset_stream(cnx, stream_id, 0);
                        context->stream_open = 0;
                        return 0;
                case picoquic_callback_stream_data:
			printf("Callback: StreamData\n");
                        if(length > 0) {
                                char data[length+1];
				memset(data, 0, length+1);
                                memcpy(data, (char*)bytes, length);
                                //printf("Server sent: %s\n", data);

				//Store data received from Server
				context->data.insert(context->data.begin(), data, data + sizeof(data));
                                if ((stream_id !=0) &&
					store_chunk(cnx, context,bytes, length, context->xid[(stream_id-1)/2], process_type) ==0){
                                        b_validate = true;
                                }
				context->data.clear(); //For get, might not need to save data onto context
                                context->received_so_far += length;
                                printf("Check data received from server: %d\n", context->received_so_far);

				/*RZ0915 ACK to SERVER : TODO Might send this after processing last xid
                        	if (context->received_so_far > 0 && b_validate) {
					printf("Callback: Client OK ACK on %s to Server!!\n", 
							context->xid[(stream_id-1)/2].c_str());
					
                                	ack_response(cnx, stream_id,1, context);
                        	} else {
					printf("Callback: Client Error response on %s to Server!!\n", 
							context->xid[(stream_id-1)/2].c_str());
                                	ack_response(cnx, stream_id,0, context);
                        	}*/
                        }
                        break;

		case picoquic_callback_stream_fin:
                        printf("Callback: stream finished\n");
			
                        if(length > 0) {
                                char data[2048];
                                memcpy(data, (char*)bytes, length);
                                data[length] = 0;
                                printf("Server sent: %s\n", data);
                                context->received_so_far += length;
                        }
                        context->stream_open = 0;
                        printf("Reception completed after %d bytes.\n",
                                        context->received_so_far);
			printf("Resetting the stream after it finished.\n");
                        picoquic_reset_stream(cnx, stream_id, 0);
			break;
                default:
                        printf("ERROR: unknown callback event %d\n", event);
        };
        return 0;
}


/*GET_Chunk_data is to retrieve the data from chunk content provider
 */
void get_chunk_data (struct addr_info_t &test_from_addr, struct addr_info_t &test_to_addr, vector <string> xid_lst,
                        picoquic_quic_t *quic_client, struct callback_context_t callback_context, int state,
                        uint64_t current_time, std::string process_type, LocalConfig &conf){

	std::cout<<"--------: "<<__FUNCTION__ << "----------"<<endl;
	//std::cout<<" ToAddr" << test_to_addr.dag->dag_string().c_str()<<endl;

	int64_t delay_max = 10000000;
        sockaddr_x packet_from;
        sockaddr_x packet_to;
        unsigned long if_index_to = 0;
        uint8_t buffer[2048];
        int bytes_recv;
        int64_t delta_t = 0;
        int established = 0;
        unsigned char received_ecn;

        // Outgoing packet buffer
        int zero_rtt_available = 0; // Flag set to 1 if 0RTT is available
	uint8_t send_buffer[2048];
        size_t send_length = 0;

        //Create connection instance
        // We didn't provide a root cert, so set verifier to null
        picoquic_set_null_verifier(quic_client);

        picoquic_cnx_t *quic_conn;
	quic_conn = picoquic_create_cnx(
                        quic_client, // QUIC context
                        picoquic_null_connection_id,        // initial connection ID
                        picoquic_null_connection_id,        // remote_connection ID
                        (struct sockaddr*) &test_to_addr.addr,
                        current_time,   // start time
                        0,              // preferred version
                        "localhost",    // Server name identifier
                        "hq-17",        // ALPN
                        1               // client mode, set to 1, if on client side
                        );

        if (quic_conn == NULL) {
                printf("ERROR: creating client connection in QUIC\n");
		goto client_done;
            }
	printf("Created QUIC connection instance\n");
        state = 4;

        //Set a callback for the client connection
	if(process_type.compare("PUT")==0) {
                picoquic_set_callback(quic_conn, client_putdata_transfer, &callback_context);
        } else {
                picoquic_set_callback(quic_conn, client_data_transfer, &callback_context);
        }

        // Now connect to the server
        if(picoquic_start_client_cnx(quic_conn)) {
                printf("ERROR: connecting to server\n");
                goto client_done;
        } else {
                printf("Check initial cnxID:  %llx\n",
                                (unsigned long long)picoquic_val64_connection_id(picoquic_get_initial_cnxid(quic_conn)));
        	printf("Started connection to server\n");
	}
	 //If 0RTT is available, start a stream
        if(picoquic_is_0rtt_available(quic_conn)) {
                cout<<"start stream function!!! for process " <<process_type.c_str()<<endl;
		put_chunk(quic_conn, &callback_context,process_type,xid_lst);
                zero_rtt_available = 1;
        }
        printf("Zero RTT available: %d\n", zero_rtt_available);

         ///////picoquic prepare receiving data
        //First send a packet to get the connection establishment started
        pthread_mutex_lock(&conf.lock);

	if(picoquic_prepare_packet(quic_conn, current_time,
                                send_buffer, sizeof(send_buffer), &send_length,
                                NULL, NULL,    // Address to
                                NULL, NULL)) { // Address from
                printf("ERROR: preparing a QUIC packet to send\n");
		pthread_mutex_unlock(&conf.lock);
                goto client_done;
        }

        printf("Prepared packet of size %zu\n", send_length);
        test_from_addr.dag->fill_sockaddr(&test_from_addr.addr);
        int bytes_sent;
        if(send_length > 0) {
                bytes_sent = picoquic_xia_sendmsg(test_from_addr.sockfd, send_buffer,
                                (int) send_length, &test_to_addr.addr, &test_from_addr.addr, conf);
                if(bytes_sent < 0) {
                        printf("ERROR: sending packet to server\n");
                        goto client_done;
                }
                printf("Sent %d byte packet to server: %s\n  from me: %s\n", bytes_sent,
                 test_to_addr.dag->dag_string().c_str(), test_from_addr.dag->dag_string().c_str());
        }
        pthread_mutex_unlock(&conf.lock);

	//Now wait for incoming packets
         printf("Connection state = %d established = %d\n",
                                    picoquic_get_cnx_state(quic_conn), established);
	
        while(picoquic_get_cnx_state(quic_conn) != picoquic_state_disconnected) {
                delay_max = 10000000;

                // Wait until data or timeout
                bytes_recv = picoquic_xia_select(test_from_addr.sockfd, &packet_from,
                                &packet_to, buffer, sizeof(buffer),
                                delta_t,
                                &current_time);
                printf("Client received %d byte packet after select \n", bytes_recv);
                // Exit on error
                if(bytes_recv < 0) {
                        printf("ERROR: receiving packet after select\n");
                        goto client_done;
                }
                // Get the connection state
                picoquic_state_enum cnx_state = picoquic_get_cnx_state(quic_conn);
                printf("Connection state: %d\n", cnx_state);

                // We have a packet to process
                if(bytes_recv > 0) {
                        //Check the packet Addresses receiving
                        printf("Condition: received packet greater than zero bytes\n");
                        Graph p_from(&packet_from);
                        Graph p_to(&packet_to);
                        std::cout<<"Packet fromAddr: "<<p_from.dag_string()<<" toAddr: "<<p_to.dag_string()<<std::endl;
                        if(picoquic_incoming_packet(quic_client, buffer,
                                                (size_t)bytes_recv, (struct sockaddr*)&packet_from,
                                                (struct sockaddr*)&packet_to, if_index_to,
                                                received_ecn,
                                                current_time)) {
                                printf("ERROR: processing incoming packet\n");
                                delta_t = 0;
                        }
                        delta_t = 0;
                }

		//Timed out. Check if connection established or stream ended
                if(bytes_recv == 0) {
                        if(cnx_state == picoquic_state_ready
                                        || cnx_state == picoquic_state_client_ready_start) {

                                // The connection is ready. Start a stream.
                                if(!established) {
                                        printf("Connected! ver: %x, I-CID: %llx\n",
                                                        picoquic_supported_versions[
                                                        quic_conn->version_index].version,
                                                        (unsigned long long)picoquic_val64_connection_id(
                                                                picoquic_get_logging_cnxid(quic_conn)));
                                        if(!zero_rtt_available) {
                                        printf("zero rtt was not available, starting stream %s\n", process_type.c_str());
					put_chunk(quic_conn, &callback_context,process_type,xid_lst);
                                        
					printf("-----------completed stream data ---------\n");

					if( callback_context.xid.size()>0){
						for (int n=0; n<callback_context.xid.size(); n++){
						 printf("Assign contextXID  %s \n", (callback_context.xid[n]).c_str());
						} 
					}else {
							printf("Empty context XID!!!!\n");
						}
                                        }
                                        established = 1;
					printf("Set connection established value: %d\n", established);
		               }
                        }
                        // If the stream has been closed, we close the connection
                        if(callback_context.connected && !callback_context.stream_open) {
                                printf("The stream was not open, close connection\n");
                                picoquic_close(quic_conn, 0);
                                quic_conn = NULL;
                                break;
                        }

                        // Waited too long. Close connection
                        if(current_time > callback_context.last_interaction_time
                                        && current_time - callback_context.last_interaction_time
                                            > 60000000ull) {
                                printf("No progress for 60 seconds. Closing\n");
                                picoquic_close(quic_conn, 0);
                                quic_conn = NULL;
                                break;
                                //goto client_done;
                        }
                } //end byte_recv zero

	  // We get here whether there was a packet or a timeout
                send_length = PICOQUIC_MAX_PACKET_SIZE;
                while(send_length > 0) {
                        //sleep(10);
                        // Send out all packets waiting to go
                        pthread_mutex_lock(&conf.lock);
                        if(picoquic_prepare_packet(quic_conn, current_time,
                                                send_buffer, sizeof(send_buffer), &send_length,
                                                NULL, NULL, NULL, NULL)) {
                                printf("ERROR sending QUIC packet\n");
                                pthread_mutex_unlock(&conf.lock);
                                goto client_done;
                        }
                        if(send_length > 0) {
                                printf("Sending packet of size %ld \n", send_length);
                                bytes_sent = picoquic_xia_sendmsg(test_from_addr.sockfd, send_buffer,
                                                (int) send_length, &test_to_addr.addr, &test_from_addr.addr, conf);
                                if(bytes_sent <= 0) {
                                        printf("ERROR sending packet to server\n");
                                }
                                printf("Sent %d byte packet to server: %s) from me: %s\n", bytes_sent,
                                        test_to_addr.dag->dag_string().c_str(), test_from_addr.dag->dag_string().c_str());
                        }
                        pthread_mutex_unlock(&conf.lock);
                }//end while send_length

                // How long before we timeout waiting for more packets
                delta_t = picoquic_get_next_wake_delay(quic_client, current_time,
                                delay_max);

        }//end while byte_recv

client_done:
        switch(state) {
                case 4:
                        if(quic_conn) {
                                picoquic_close(quic_conn, 0); // 0 = reason code
                        }
                case 2:
                        picoquic_free(quic_client);
                case 1:
                        close(test_from_addr.sockfd);
        };
        return;
}

/* Client(requestor) sends ack to Server(content provider) after received stream data
 * @param streamid: the last stream data to be finished on Client
 * 	  connecton: current quic connection instance
 * 	  callback_context: context assoicated to the quic connection
 * @return: void
 * */
void ack_response(picoquic_cnx_t* connection, uint64_t stream_id, int resp_code,  struct callback_context_t* context)
{
	char ack_str[100]= "OK ACK: ";

        if (resp_code==0){
                strcpy(ack_str,"ERROR ACK: ");
        }
	strcat(ack_str, (context->xid[(stream_id -1)/2]).c_str());
        picoquic_add_to_stream(connection,
        stream_id+101, // Any arbitrary stream ID client picks
                                (uint8_t*)ack_str, sizeof(ack_str), // data to be sent
                               1);
}
