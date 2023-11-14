set (TARGET OnlyCryptopp)
set (OUTPUT_NAME OnlyCryptopp)
set (CMAKE_INCLUDE_CURRENT_DIR ON)
set (FOLDER "OnlyCryptopp")

set (SOURCE_FILES
        Main.cpp
)

add_executable(${TARGET} ${SOURCE_FILES})

target_link_libraries(${TARGET}
                            PUBLIC
                            cryptopp::cryptopp
                            libpqxx::pqxx)

set_target_properties(${TARGET} PROPERTIES
    LINKER_LANGUAGE CXX
    FOLDER ${FOLDER})

target_include_directories(${TARGET} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/)
