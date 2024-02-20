#!/bin/sh
#-----------------------------
BASE=$(dirname $0)
#-----------------------------

#-----------------------------
make_root_certificate() {
	local name=${1:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$name.key.der
	certtool \
		--generate-self-signed \
		--template=templ-root.cfg \
		--load-privkey=$name.key.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$name.der
}
#-----------------------------
make_sub_certificate() {
	local name=${1:-sub} auth=${2:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$name.key.der
	certtool \
		--generate-certificate \
		--template=templ-sub.cfg \
		--load-privkey=$name.key.der \
		--load-ca-privkey=$auth.key.der \
		--load-ca-certificate=$auth.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$name.der
	cat $name.der $auth.der > $name.list.der
}
#-----------------------------
make_end_certificate() {
	local name=${1:-end} auth=${2:-sub}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$name.key.der
	certtool \
		--generate-certificate \
		--template=templ-end.cfg \
		--load-privkey=$name.key.der \
		--load-ca-privkey=$auth.key.der \
		--load-ca-certificate=$auth.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$name.der
	cat $name.der $auth.list.der > $name.list.der
}
#-----------------------------
make_root_certificate root
make_sub_certificate  sub
make_end_certificate  end

make_root_certificate root2
make_sub_certificate  sub2 root2
make_end_certificate  end2 sub2
