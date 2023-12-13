# XIA integration environment

## Software requirements
### Docker version 20.10.8 if setting up environment via Docker

### Software and packages for environment setup without Docker:
+ Install dependencies using Advanced Packaging Tool(apt): build-essential, cmake, pkg_config, libprotobuf-dev, libxml2, libxml2-dev, libxslt1-dev, protobuf-compiler, 
							   libssl-dev, openssl, swig 
+ Install Python packages required via requirements.txt: pip install -r requirements.txt

## Main programs
#### xia configuration: The xia-core source code serves the xia overlay configuration functions. It involves two main utilities: configurator and confighelper. The configurator reads in initial configuration files, setup the topology, and  communicate to the confighelper via protocol buffers to configure the routers and endpoints

#### picoquic-xia-integration libraries: The libraries contains picoquic-core library and the libraries and modules that utilize xia packets transmission through quic protocol over XIA network structure 
+ picoquic-core: picoquic, picoquictest, picoquic_t, and the picoquic core test program picoquicfirst
+ xia libraries: xia-api-lib, localConfig-lib and contentchunk-lib
+ xia modules: xCache module, put-get-communication module, routing-forwarding-engine module

#### application-api-test: Contains functions&files planned for application api implementation. 
 



