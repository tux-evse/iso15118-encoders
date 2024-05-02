add_executable(test-iso2-sign test-iso2-sign.c)
target_include_directories(test-iso2-sign PRIVATE ../encoders/common ../encoders/utils ../encoders/iso-2)
target_link_libraries(test-iso2-sign PRIVATE iso15118)