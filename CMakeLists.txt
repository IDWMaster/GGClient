cmake_minimum_required(VERSION 2.6)
project(ggclient)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(GGLib_SRCS cppext/cppext.cpp crypto.cpp database.cpp sqlite3.c)
set(GGClient_SRCS main.cpp)
set(GGRouter_SRCS router.cpp)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_library(gglib SHARED ${GGLib_SRCS})
add_executable(ggclient ${GGClient_SRCS})
add_executable(ggrouter ${GGRouter_SRCS})

target_link_libraries(gglib pthread dl rt uuid crypto ssl)
target_link_libraries(ggclient gglib)
target_link_libraries(ggrouter gglib)

install(TARGETS ggclient RUNTIME DESTINATION bin)
install(TARGETS gglib LIBRARY DESTINATION lib)

