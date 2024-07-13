cmake_minimum_required(VERSION 3.7)
PROJECT(quic-fiber)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH})

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "$ENV{CXXFLAGS} -rdynamic -O0 -ggdb -g -std=c++17 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined")
#set(CMAKE_CXX_FLAGS "$ENV{CXXFLAGS} -rdynamic -O3 -std=c++17 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined")
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

include_directories("./" "./tests")

find_library(YAMLCPP yaml-cpp /usr/local/lib/)
find_library(THREAD pthread /usr/lib64/)
find_library(GTEST gtest /usr/local/lib64/)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

set(LIBS ${PROJECT_NAME}
        my_sylar
        pthread
        yaml-cpp
        dl
        gtest
        #jemalloc
        ${OPENSSL_LIBRARIES}
        )

set(LIB_SRC
        quic-fiber/quic_type.cc
        quic-fiber/quic_frame.cc
        quic-fiber/quic_stream.cc
        quic-fiber/quic_frame_sorter.cc
        quic-fiber/quic_packet.cc
        quic-fiber/quic_session.cc
        quic-fiber/quic_packet_sorter.cc
        quic-fiber/quic_utils.cc
        quic-fiber/quic_server.cc
        quic-fiber/quic_congestion.cc
        quic-fiber/quic_flow_control.cc
        quic-fiber/quic/bbr/bbr_utils.cc
        quic-fiber/quic/bbr/bbr_sender.cc
        )

add_library(${PROJECT_NAME} SHARED ${LIB_SRC})

function(quic_fiber_add_executable targetname srcs depends libs)
    add_executable(${targetname} ${srcs})
    add_dependencies(${targetname} ${depends})
    #force_redefine_file_macro_for_source(${targetname})
    target_link_libraries(${targetname} ${libs})
endfunction()

quic_fiber_add_executable(quic_server tests/server.cc ${PROJECT_NAME} "${LIBS}")
quic_fiber_add_executable(quic_client tests/client.cc ${PROJECT_NAME} "${LIBS}")
quic_fiber_add_executable(udp_rs tests/udp_rs.cc ${PROJECT_NAME} "${LIBS}")
quic_fiber_add_executable(semaphore_test tests/semaphore_test.cc ${PROJECT_NAME} "${LIBS}")
