# ISO15118 (din,2,20) encoders

Those encoder are generated from ISO15118 XDS schema with Chargebyte cbexigen

References:
* chargebyte: https://github.com/EVerest/cbexigen.git
* iso: https://standards.iso.org/iso/15118/
* din https://github.com/FlUxIuS/V2Gdecoder/tree/master/schemas_din

While ISO xsd are public, you need to agree to license before using them

## Regenerating XDI encoders

regenerating encoder is only needed to update to a newer ISO-15118 specifications

* install cbexigen on your system
* download XSD from from iso.org web site
* organize xsd files as expected by cbexigen
* start cbexigen code generator

# compilation

```
# mkdir build && cd build
# cmake -DCMAKE_BUILD_TYPE=Release ..
# cmake -DCMAKE_BUILD_TYPE=Debug ..
```

**schema should be organized as follow**
```
src/input/schemas/
└── iso-2
    ├── DIN_70121
    │   ├── V2G_CI_AppProtocol.xsd
    │   ├── V2G_CI_MsgBody.xsd
    │   ├── V2G_CI_MsgDataTypes.xsd
    │   ├── V2G_CI_MsgDef.exig
    │   ├── V2G_CI_MsgDef.xsd
    │   ├── V2G_CI_MsgHeader.xsd
    │   ├── V2G_DIN_MsgDef.xsd
    │   └── xmldsig-core-schema.xsd
    ├── ISO_15118-2
    │   └── FDIS
    │       ├── V2G_CI_AppProtocol.xsd
    │       ├── V2G_CI_MsgBody.xsd
    │       ├── V2G_CI_MsgDataTypes.xsd
    │       ├── V2G_CI_MsgDef.xsd
    │       ├── V2G_CI_MsgHeader.xsd
    │       └── xmldsig-core-schema.xsd
    └── ISO_15118-20
        └── FDIS
            ├── V2G_CI_ACDP.xsd
            ├── V2G_CI_AC.xsd
            ├── V2G_CI_AppProtocol.xsd
            ├── V2G_CI_CommonMessages.xsd
            ├── V2G_CI_CommonTypes.xsd
            ├── V2G_CI_DC.xsd
            ├── V2G_CI_WPT.xsd
            └── xmldsig-core-schema.xsd

```

**update src/encoders directory with newly generated files**
```
src/output/c/
├── appHandshake
│   ├── appHand_Datatypes.c
│   ├── appHand_Datatypes.h
│   ├── appHand_Decoder.c
│   ├── appHand_Decoder.h
│   ├── appHand_Encoder.c
│   └── appHand_Encoder.h
├── common
│   ├── exi_basetypes.c
│   ├── exi_basetypes_decoder.c
│   ├── exi_basetypes_decoder.h
│   ├── exi_basetypes_encoder.c
│   ├── exi_basetypes_encoder.h
│   ├── exi_basetypes.h
│   ├── exi_bitstream.c
│   ├── exi_bitstream.h
│   ├── exi_error_codes.h
│   ├── exi_header.c
│   ├── exi_header.h
│   ├── exi_types_decoder.c
│   └── exi_types_decoder.h
├── din
│   ├── din_msgDefDatatypes.c
│   ├── din_msgDefDatatypes.h
│   ├── din_msgDefDecoder.c
│   ├── din_msgDefDecoder.h
│   ├── din_msgDefEncoder.c
│   └── din_msgDefEncoder.h
├── iso-2
│   ├── iso2_msgDefDatatypes.c
│   ├── iso2_msgDefDatatypes.h
│   ├── iso2_msgDefDecoder.c
│   ├── iso2_msgDefDecoder.h
│   ├── iso2_msgDefEncoder.c
│   └── iso2_msgDefEncoder.h
├── iso-20
│   ├── iso20_AC_Datatypes.c
│   ├── iso20_AC_Datatypes.h
│   ├── iso20_AC_Decoder.c
│   ├── iso20_AC_Decoder.h
│   ├── iso20_ACDP_Datatypes.c
│   ├── iso20_ACDP_Datatypes.h
│   ├── iso20_ACDP_Decoder.c
│   ├── iso20_ACDP_Decoder.h
│   ├── iso20_ACDP_Encoder.c
│   ├── iso20_ACDP_Encoder.h
│   ├── iso20_AC_Encoder.c
│   ├── iso20_AC_Encoder.h
│   ├── iso20_CommonMessages_Datatypes.c
│   ├── iso20_CommonMessages_Datatypes.h
│   ├── iso20_CommonMessages_Decoder.c
│   ├── iso20_CommonMessages_Decoder.h
│   ├── iso20_CommonMessages_Encoder.c
│   ├── iso20_CommonMessages_Encoder.h
│   ├── iso20_DC_Datatypes.c
│   ├── iso20_DC_Datatypes.h
│   ├── iso20_DC_Decoder.c
│   ├── iso20_DC_Decoder.h
│   ├── iso20_DC_Encoder.c
│   ├── iso20_DC_Encoder.h
│   ├── iso20_WPT_Datatypes.c
│   ├── iso20_WPT_Datatypes.h
│   ├── iso20_WPT_Decoder.c
│   ├── iso20_WPT_Decoder.h
│   ├── iso20_WPT_Encoder.c
│   └── iso20_WPT_Encoder.h
└── v2gtp
    ├── exi_v2gtp.c
    └── exi_v2gtp.h

```