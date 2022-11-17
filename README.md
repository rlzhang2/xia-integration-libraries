# XIA integration environment

## Software requirements
### Docker version 20.10.8 if setting up environment via Docker

### Software and packages for environment setup without Docker:
+ install: build-essential, cmake, pkg_config, libprotobuf-dev, libxml2-dev, libxslt1-dev, protobuf-compiler, libssl-dev, python-config 
+ Python packages required via requirements.txt: pip install -r requirements.txt

## Main programs
+ xia configuration: The program involves two main utilities: configurator and confighelper. The configurator reads in initial configuration files, setup the topology, and  communicate to the confighelper via protocol buffers to configure the routers and endpoints

+ xia libraries: The libraries contains the picoquic-core library and XIA api libraries to utilize packets transmition through quic protocol over XIA network structure 

+ xia modules: Includes  xCache module, put/get-contents communication module, routing and forwarding module.


 



