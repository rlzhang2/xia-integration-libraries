cmake_minimum_required(VERSION 3.0.2)
cmake_policy(SET CMP0003 NEW)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(ExternalProject)
include(TestBigEndian)
project(picoquic)

add_definitions(-DCLICK_BIG_ENDIAN=4321)
add_definitions(-DCLICK_LITTLE_ENDIAN=1234)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
 add_definitions(-DCLICK_BYTE_ORDER=4321)
else()
 message(STATUS "LITTLE_ENDIAN")
 add_definitions(-DCLICK_BYTE_ORDER=1234)
endif()

# XIA codebase
ExternalProject_Add(xia
    GIT_REPOSITORY https://github.com/XIA-Project/xia-core.git
    GIT_TAG xia-v2-overlay-ruilingz
    CONFIGURE_COMMAND ./configure
    BUILD_COMMAND make DEBUG=1
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND ""
    )


# PicoTLS codebase - as a git submodule
add_subdirectory(picotls)

set(CMAKE_C_STANDARD 11)

# FIND_PACKAGE(PkgConfig REQUIRED)

set(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    set(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

set(LOCAL_CONFIG_FILES
    localConfig-lib/localconfig.cpp
)

set(PICOQUIC_XIA_API_FILES
    xia-api-lib/xiaapi.cpp
    xia-api-lib/quicxiasock.cpp
)

set(PICOQUIC_CHUNKLIB_FILES
    contentchunk-lib/chunkapi.cpp
    contentchunk-lib/chunkhash.cpp
    contentchunk-lib/get_putChunkapi.cpp
    contentchunk-lib/publisher.cc
)

set(PICOQUIC_XCACHE_FILES
  xcache/xcache.cc
  xcache/xcache_thread_pool.cc
  xcache/xcache_quic.cc
  xcache/xcache_quic_server.cc
   xcache/xcache_icid_handler.cc
  xcache/fd_manager.cc

  xcache/xcache_push_request.cc
  xcache/xcache_receive_request.cc
  xcache/xcache_irq_table.cc
)

set(PICOQUIC_LIBRARY_FILES
    picoquic/cubic.c
    picoquic/democlient.c
    picoquic/demoserver.c
    picoquic/fnv1a.c
    picoquic/frames.c
    picoquic/h3zero.c
    picoquic/http0dot9.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/newreno.c
    picoquic/packet.c
    picoquic/picohash.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/spinbit.c
    picoquic/ticket_store.c
    picoquic/token_store.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/util.c
)

set(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/ack_of_ack_test.c
    picoquictest/cleartext_aead_test.c
    picoquictest/cnx_creation_test.c
    picoquictest/float16test.c
    picoquictest/fnv1atest.c
    picoquictest/h3zerotest.c
    picoquictest/hashtest.c
    picoquictest/http0dot9test.c
    picoquictest/intformattest.c
    picoquictest/parseheadertest.c
    picoquictest/pn2pn64test.c
    picoquictest/sacktest.c
    picoquictest/skip_frame_test.c
    picoquictest/sim_link.c
    picoquictest/socket_test.c
    picoquictest/splay_test.c
    picoquictest/stream0_frame_test.c
    picoquictest/stresstest.c
    picoquictest/ticket_store_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
)

set(PTLS_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/picotls/include)
set(CONF_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/localConfig-lib)

find_package(OpenSSL )
message(STATUS "root: ${OPENSSL_ROOT_DIR}")
message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

find_package(Protobuf REQUIRED)
file(GLOB ProtoFiles "${CMAKE_CURRENT_SOURCE_DIR}/picoquic/*.proto")
PROTOBUF_GENERATE_CPP(ProtoSources ProtoHeaders ${ProtoFiles})
#add_library(confreqmsgs STATIC ${ProtoSources} ${ProtoHeaders})
#target_link_libraries(confreqmsgs ${PROTOBUF_LIBRARY})
set(ProtobufIncludePath ${CMAKE_CURRENT_BINARY_DIR}
    CACHE INTERNAL "Path to generated ConfigRequest messages protobuf files.")

include_directories(picoquic picoquictest ${ProtobufIncludePath}
    ${PTLS_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${CONF_INCLUDE_DIRS})

# Build XIA API and protobuf defs to configure forwarding table on router
add_library(picoquicxia ${PICOQUIC_XIA_API_FILES}
    ${ProtoSources} ${ProtoHeaders})
add_dependencies(picoquicxia xia)

set(XIADIR ${CMAKE_SOURCE_DIR}/build/xia-prefix/src/xia)
set(DAG_LIBRARY ${XIADIR}/api/lib/libdagaddr.so)
target_link_libraries(picoquicxia ${PROTOBUF_LIBRARY} ${DAG_LIBRARY})
include_directories(picoquicxia ${XIADIR}/api/include ${CONF_INCLUDE_DIRS})

add_library(localconfig ${LOCAL_CONFIG_FILES}
    ${ProtoSources} ${ProtoHeaders})

add_library(picoquic-core
    ${PICOQUIC_LIBRARY_FILES}
)
include_directories(picoquic-core ${XIADIR}/api/include)
add_dependencies(picoquic-core xia)

set(PTLS_HINTS ${CMAKE_BINARY_PATH}/picotls picotls)
set(PTLS_LIBRARIES picotls-core picotls-minicrypto picotls-openssl)
add_executable(picoquicdemo picoquicfirst/picoquicdemo.c
                            picoquicfirst/getopt.c )
target_link_libraries(picoquicdemo picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

add_executable(picoquicclient picoquicfirst/picoquicclient.c)
target_link_libraries(picoquicclient picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

add_executable(picoquicserver picoquicfirst/picoquicserver.c)
target_link_libraries(picoquicserver picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

#xia application
find_package( Threads )
add_executable(picoquicclientxia put-get-communication/picoquicclientxia.cpp)
target_link_libraries(picoquicclientxia picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicclientxia ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

set(XCACHEHDR_LIBRARY ${XIADIR}/api/lib/libxcachehdr.so)
set(XCACHE_LIBRARY ${XIADIR}/api/lib/libxcache.so)
set(XSOCKET_LIBRARY ${XIADIR}/api/lib/libXsocket.so)

# Add XIACHUNK LIB
add_library(picoquic-chunk
    ${PICOQUIC_CHUNKLIB_FILES}
)
target_link_libraries(picoquic-chunk ${XCACHEHDR_LIBRARY} ${XCACHE_LIBRARY} ${XSOCKET_LIBRARY})
include_directories(picoquic-chunk ${XIADIR}/api/include)
add_dependencies(picoquic-chunk xia)

#Add get-put applications
find_package( Threads )
add_executable(picoquicclientxiaget put-get-communication/picoquicclientxiaget.cpp)
target_link_libraries(picoquicclientxiaget picoquic-chunk picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicclientxiaget ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(picoquicserverxiaget put-get-communication/picoquicserverxiaget.cpp)
target_link_libraries(picoquicserverxiaget picoquic-chunk picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicserverxiaget ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(picoquicclientxiapush put-get-communication/picoquicclientxiapush.cpp)
target_link_libraries(picoquicclientxiapush picoquic-chunk picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicclientxiapush ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(picoquicserverxiapush put-get-communication/picoquicserverxiapush.cpp)
target_link_libraries(picoquicserverxiapush picoquic-chunk picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicserverxiapush ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(xcacheclient  put-get-communication/xcacheclient.cpp)
target_link_libraries(xcacheclient picoquic-core picoquicxia
  localconfig
  ${XCACHEHDR_LIBRARY}
  ${XCACHE_LIBRARY}
  ${PTLS_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
)
include_directories(xcacheclient ${XIADIR}/api/xcache/headers)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(picoquicserverxia put-get-communication/picoquicserverxia.cpp)
target_link_libraries(picoquicserverxia picoquic-core picoquicxia
    localconfig
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PROTOBUF_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)
include_directories(picoquicserverxia ${XIADIR}/api/include)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

find_package( Threads )
add_executable(xcache ${PICOQUIC_XCACHE_FILES})
target_link_libraries(xcache picoquic-core picoquicxia
  localconfig
  ${XCACHEHDR_LIBRARY}
  ${XCACHE_LIBRARY}
  ${PTLS_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${PROTOBUF_LIBRARY}
  ${CMAKE_THREAD_LIBS_INIT}
  ${XSOCKET_LIBRARY}
  ${CMAKE_DL_LIBS}
)
include_directories(xcache ${XIADIR}/api/xcache/headers)
include_directories(xcache ${XIADIR}/api/xcache)
include_directories(picoquiccleinetxia ${CONF_INCLUDE_DIRS})

add_executable(picoquic_ct picoquic_t/picoquic_t.c
 ${PICOQUIC_TEST_LIBRARY_FILES} )
target_link_libraries(picoquic_ct picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

set(TEST_EXES picoquic_ct)

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES}
)
