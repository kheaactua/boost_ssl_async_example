project(BOOST_SSL_EX)

cmake_minimum_required(VERSION 3.10)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
	message("Using toolchain: ${CMAKE_TOOLCHAIN_FILE}")
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

find_package(Boost 1.72 REQUIRED COMPONENTS system date_time)
find_package(OpenSSL REQUIRED)

file(GLOB HEADERS include/ex/*.h*)
file(GLOB SRC ex/*.cpp)

add_library(sslex ${SRC} ${HEADERS})
set_source_files_properties(ex/ex.cpp PROPERTIES COMPILE_FLAGS /bigobj)
target_include_directories(sslex PUBLIC include ${Boost_INCLUDE_DIRS})
set_property(TARGET sslex PROPERTY CXX_STANDARD 14)
target_link_libraries(sslex
	PUBLIC
		${Boost_LIBRARIES}
		OpenSSL::SSL OpenSSL::Crypto
)
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
target_compile_definitions(sslex PUBLIC
	COMPILING_DLL
	_UNICODE UNICODE
	# D_WIN32_WINNT=0x0A00 _WIN32_WINNT=0x0A00
)
target_precompile_headers(sslex PUBLIC include/ex/pch.h)


add_executable(app main.cpp pch.h)
set_source_files_properties(main.cpp PROPERTIES COMPILE_FLAGS /bigobj)
target_include_directories(app PUBLIC ${PROJECT_SOURCE_DIR})
set_property(TARGET app PROPERTY CXX_STANDARD 14)
target_link_libraries(app
	PRIVATE
		sslex
)
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
target_compile_definitions(app PUBLIC
	_UNICODE UNICODE
	D_WIN32_WINNT=0x0A00 _WIN32_WINNT=0x0A00
)
target_precompile_headers(app PUBLIC pch.h)

#  vim: set ts=2 sw=2 sts=2 tw=10 noet :
