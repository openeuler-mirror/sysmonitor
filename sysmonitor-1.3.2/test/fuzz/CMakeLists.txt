project(sysmonitor)

execute_process(COMMAND bash "-c" "rpm -qil compiler-rt | grep lib/libclang_rt.fuzzer-*.a"
                OUTPUT_VARIABLE LIB_FUZZING_ENGINE
                OUTPUT_STRIP_TRAILING_WHITESPACE)

IF(LIB_FUZZING_ENGINE STREQUAL "")
    MESSAGE(WARNING "LIB_FUZZING_ENGINE is NULL, will ignore directory <fuzz> compile")
    RETURN()
ENDIF()

MESSAGE(STATUS "LIB_FUZZING_ENGINE is set to ${LIB_FUZZING_ENGINE}")

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize-coverage=trace-pc")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize-coverage=trace-pc")
ENDIF()

INCLUDE_DIRECTORIES(../../src)

SET(EXE sysmonitor_fuzz)

add_executable(${EXE}
    sysmonitor_fuzz.c
    ../../src/common.c
    ../common_interface/common_interface.c)

set_target_properties(${EXE} PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(${EXE} ${LIB_FUZZING_ENGINE} pthread securec)

