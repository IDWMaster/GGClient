cmake_minimum_required(VERSION 2.6)
project(ggclient)
find_package(Qt4 REQUIRED)

include_directories(${QT_INCLUDES} ${CMAKE_CURRENT_BINARY_DIR})

set(GGClient_SRCS GGClient.cpp main.cpp)

qt4_automoc(${GGClient_SRCS})
add_executable(ggclient ${GGClient_SRCS})
target_link_libraries(ggclient ${QT_QTCORE_LIBRARY})

install(TARGETS ggclient RUNTIME DESTINATION bin)
