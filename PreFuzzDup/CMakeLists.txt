cmake_minimum_required(VERSION 3.22)
project(PreFuzzDup LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PREFUZZDUP_ENABLE_MEDIA "Enable OpenCV image tag adapter" OFF)

set(OPENSSL_ROOT_DIR "" CACHE PATH "OpenSSL installation prefix")
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(SQLite3 REQUIRED)

add_executable(prefuzzdup src/main.cpp)
target_link_libraries(prefuzzdup PRIVATE OpenSSL::Crypto SQLite::SQLite3)
target_compile_options(prefuzzdup PRIVATE -O3 -Wall -Wextra -Wpedantic)

add_executable(prefuzzdup_persistent_lookup src/persistent_lookup.cpp)
target_link_libraries(prefuzzdup_persistent_lookup PRIVATE OpenSSL::Crypto SQLite::SQLite3)
target_compile_options(prefuzzdup_persistent_lookup PRIVATE -O3 -Wall -Wextra -Wpedantic)

if(PREFUZZDUP_ENABLE_MEDIA)
  find_package(OpenCV REQUIRED COMPONENTS core imgproc imgcodecs)
  target_link_libraries(prefuzzdup PRIVATE ${OpenCV_LIBS})
  target_compile_definitions(prefuzzdup PRIVATE PREFUZZDUP_ENABLE_MEDIA=1)
endif()
