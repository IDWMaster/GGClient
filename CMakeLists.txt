cmake_minimum_required(VERSION 2.6)
project(ggclient)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(GGClient_SRCS main.cpp cppext/cppext.cpp crypto.cpp database.cpp sqlite3.c)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_executable(ggclient ${GGClient_SRCS})
target_link_libraries(ggclient pthread dl rt uuid crypto ssl)

install(TARGETS ggclient RUNTIME DESTINATION bin)
