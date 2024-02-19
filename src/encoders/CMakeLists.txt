
# generic Linux option
add_compile_options("-fPIC")

# exi codec is statically linked with iso15118-2x share lib
add_library(cb_exi_codec)
target_compile_features(cb_exi_codec PRIVATE c_std_99)

# Build cb_exi_codec
file(GLOB EXI_SRC common/exi_*.c)
file(GLOB EXI_INC common/exi_*.h)
target_sources(cb_exi_codec
    PRIVATE
    ${EXI_SRC}
)

target_include_directories(cb_exi_codec
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/common
)

# Build libiso15118 -20 & -2
file(GLOB ISO20_SRC appHandshake/*.c iso-20/*.c iso-2/*.c v2gtp/*.c din/*.c sdp-encoders/*.c)
file(GLOB ISO20_INC appHandshake/*.h iso-20/*.h iso-2/*.h v2gtp/*.h din/*.h sdp-encoders/*.h)
add_library(iso15118 SHARED ${ISO20_SRC})
target_compile_features(iso15118 PRIVATE c_std_99)

target_include_directories(iso15118
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/iso-20
        ${CMAKE_CURRENT_SOURCE_DIR}/iso-2
        ${CMAKE_CURRENT_SOURCE_DIR}/common
)

target_link_libraries(iso15118
    PRIVATE
        cb_exi_codec
)

set_target_properties (iso15118 PROPERTIES
	PUBLIC_HEADER "${ISO20_INC}"
    LIBRARY_OUTPUT_DIRECTORY "lib64"
	VERSION "${PROJECT_VERSION}"
    )

set_target_properties (cb_exi_codec PROPERTIES
	PUBLIC_HEADER "${EXI_INC}"
    LIBRARY_OUTPUT_DIRECTORY "lib64"
	VERSION "${PROJECT_VERSION}"
    )

install(TARGETS iso15118
    PUBLIC_HEADER DESTINATION include/iso15118
    LIBRARY DESTINATION lib64
)

install(TARGETS cb_exi_codec
    PUBLIC_HEADER DESTINATION include/cb_exi_codec
    LIBRARY DESTINATION lib64
)