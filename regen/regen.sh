#!/bin/bash

root=$(realpath $(dirname $0))

bon=true
echo checking installed python libraries
for rp in xmlschema jinja2
do
	echo -n "check of python package $rp "
	if pip -q show $rp >&/dev/null
	then
		echo "found"
	else
		echo "missing!"
		bon=false
	fi
done

$bon || exit

mkdir -p $root/schemas

if ! [[ -d $root/schemas/iso-2 ]]
then
        mkdir -p $root/schemas/iso-2
        for x in \
                V2G_CI_AppProtocol.xsd \
                V2G_CI_MsgBody.xsd \
                V2G_CI_MsgDataTypes.xsd \
                V2G_CI_MsgDef.xsd \
                V2G_CI_MsgHeader.xsd \
                xmldsig-core-schema.xsd
        do
                echo "reading iso-2 $x"
                curl -s -o $root/schemas/iso-2/$x https://standards.iso.org/iso/15118/-2/ed-2/en/$x || bon=false
        done
fi

if ! [[ -d $root/schemas/iso-20 ]]
then
        mkdir -p $root/schemas/iso-20
        for x in \
                V2G_CI_ACDP.xsd \
                V2G_CI_AC.xsd \
                V2G_CI_AppProtocol.xsd \
                V2G_CI_CommonMessages.xsd \
                V2G_CI_CommonTypes.xsd \
                V2G_CI_DC.xsd \
                V2G_CI_WPT.xsd \
                xmldsig-core-schema.xsd
        do
                echo "reading iso-20 $x"
                curl -s -o $root/schemas/iso-20/$x https://standards.iso.org/iso/15118/-20/ed-1/en/$x || bon=false
        done
fi

if ! [[ -d $root/schemas/din ]]
then
        mkdir -p $root/schemas/din
        for x in \
                V2G_CI_AppProtocol.xsd \
                V2G_CI_MsgBody.xsd \
                V2G_CI_MsgDataTypes.xsd \
                V2G_CI_MsgDef.exig \
                V2G_CI_MsgDef.xsd \
                V2G_CI_MsgHeader.xsd \
                V2G_DIN_MsgDef.xsd \
                xmldsig-core-schema.xsd
        do
                echo "reading din $x"
                curl -s -o $root/schemas/din/$x https://raw.githubusercontent.com/FlUxIuS/V2Gdecoder/master/schemas_din/$x || bon=false
        done
fi
$bon || exit

if ! [[ -d $root/cbexigen ]]
then
        git clone https://github.com/EVerest/cbexigen.git || bon=false
fi
$bon || exit

rm -rf $root/output

sed "s,@ROOT@,$root,g" $root/pre-local-config.py > $root/local-config.py
PYTHONPATH=$root:$PYTHONPATH python3 $root/cbexigen/src/main.py --config_file $root/local-config.py

