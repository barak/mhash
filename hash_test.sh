#! /bin/sh

# $Id: hash_test.sh,v 1.1 1999/07/14 12:27:35 sascha Exp $

if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null; then
  if (echo $ac_n testing; echo 1,2,3) | sed s/-n/xn/ | grep xn >/dev/null; then
    ac_n= ac_c='
' ac_t='    '
  else
    ac_n=-n ac_c= ac_t=
  fi
else
  ac_n= ac_c='\c' ac_t=
fi

test_hash ( ) {
	if test "$#" != "3" ; then
		echo "usage: test_hash id plain expected"
		exit 1
	fi
	
	plainlen=`echo $ac_n "$2$ac_c" | wc -c`
	
	got=`echo $ac_n "$2$ac_c" | ./driver $1 $plainlen`

	want=`echo $ac_n "$3$ac_c" | tr a-z A-Z`
	
	if test "$got" != "$want" ; then
		echo "  -- TEST FAILED: $1 \"$2\""
		echo "got \"$got\""
		echo "but expected \"$want\""
		exit 1
	fi
	echo $ac_n ".$ac_c"
}

echo $ac_n "testing MD5 $ac_c"
test_hash 1 "" D41D8CD98F00B204E9800998ECF8427E
test_hash 1 a 0CC175B9C0F1B6A831C399E269772661
test_hash 1 abc 900150983CD24FB0D6963F7D28E17F72
test_hash 1 "message digest" F96B697D7CB7938D525A2F31AAF161D0
test_hash 1 abcdefghijklmnopqrstuvwxyz C3FCD3D76192E4007DFB496CCA67E13B
test_hash 1 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		D174AB98D277D9F5A5611C2C9F419D9F
test_hash 1 12345678901234567890123456789012345678901234567890123456789012345678901234567890 \
		57EDF4A22BE3C955AC49DA2E2107B67A
echo ""

echo $ac_n "testing SHA1 $ac_c"
test_hash 2 abc A9993E364706816ABA3E25717850C26C9CD0D89D
test_hash 2 abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq \
		84983E441C3BD26EBAAE4AA1F95129E5E54670F1
echo ""

echo $ac_n "testing HAVAL $ac_c"
test_hash 3 abcdefghijklmnopqrstuvwxyz \
		1A1DC8099BDAA7F35B4DA4E805F1A28FEE909D8DEE920198185CBCAED8A10A8D
test_hash 3 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		C5647FC6C1877FFF96742F27E9266B6874894F41A08F5913033D9D532AEDDB39
echo 

echo $ac_n "testing RIPEMD160 $ac_c"
test_hash 4 "" 9c1185a5c5e9fc54612808977ee8f548b2258d31
test_hash 4 a 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe
test_hash 4 abc 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
test_hash 4 "message digest" 5d0689ef49d2fae572b881b123a85ffa21595f36
test_hash 4 abcdefghijklmnopqrstuvwxyz f71c27109c692c1b56bbdceb5b9d2865b3708dbc
test_hash 4 abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq \
		12a053384a9c0c88e405a06c27dcf49ada62eb2b
test_hash 4 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		b0e20b6e3116640286ed3a87a5713079b21f5189
echo ""

echo $ac_n "testing RIPEMD128 $ac_c"
test_hash 5 "" cdf26213a150dc3ecb610f18f6b38b46
test_hash 5 a 86be7afa339d0fc7cfc785e72f578d33
test_hash 5 abc c14a12199c66e4ba84636b0f69144c77
test_hash 5 "message digest" 9e327b3d6e523062afc1132d7df9d1b8
test_hash 5 abcdefghijklmnopqrstuvwxyz fd2aa607f71dc8f510714922b371834e
test_hash 5 abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq \
		a1aa0689d0fafa2ddc22e88b49133a06
test_hash 5 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		d1e959eb179c911faea4624c60c5c702
echo ""

# the TIGER test program displays values in the wrong endian
echo $ac_n "testing TIGER $ac_c"
test_hash 7 "" 3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3
test_hash 7 abc 2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93
test_hash 7 Tiger DD00230799F5009FEC6DEBC838BB6A27DF2B9D6F110C7937
test_hash 7 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+- \
		 F71C8583902AFB879EDFE610F82C0D4786A3A534504486B5
test_hash 7 "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789" \
		48CEEB6308B87D46E95D656112CDF18D97915F9765658957
test_hash 7 "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham" \
		 8A866829040A410C729AD23F5ADA711603B3CDD357E4C15E
test_hash 7 "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge." \
		 CE55A6AFD591F5EBAC547FF84F89227F9331DAB0B611C889
test_hash 7 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-" \
		 C54034E5B43EB8005848A7E0AE6AAC76E4FF590AE715FD25
echo

echo $ac_n "testing GOST $ac_c"
test_hash 8 "This is message, length=32 bytes" \
		B1C466D37519B82E8319819FF32595E047A28CB6F83EFF1C6916A815A637FFFA
test_hash 8 "Suppose the original message has length = 50 bytes" \
		471ABA57A60A770D3A76130635C1FBEA4EF14DE51F78B4AE57DD893B62F55208
echo ""



echo "everything seems to be fine :-)"

exit 0