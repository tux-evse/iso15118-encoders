add_executable(test-iso-2-utils test-iso-2-utils.c)
target_include_directories(test-iso-2-utils PRIVATE ../encoders/common ../encoders/utils ../encoders/iso-2)
target_link_libraries(test-iso-2-utils PRIVATE iso15118)