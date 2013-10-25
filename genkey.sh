#!/bin/sh
#
# genkey.sh for rsa.php
#
# (C) Copyright 2011 - 2013 Oliver Mueller, http://oliver-mueller.com/
#
# Licensed under the terms of the GNU Public License (GPL)
# See file gpl-2.0.txt for details or alternatively
# http://www.gnu.org/licenses/gpl-2.0.txt
# or
# http://oliver-mueller.com/licenses/gpl-2.0.txt

if [ -z "$1" -o -n "$2" ]; then
	echo "Usage: ${0##*/} key-length" >&2
	exit 255
fi

# Key length
MYKEYLEN=$1

openssl genrsa $MYKEYLEN | openssl rsa -text -noout | awk '
$1 == "modulus:"           { mode = 1; next }
$1 == "privateExponent:"   { mode = 2; next }
$1 == "publicExponent:"    {
	e = sprintf("%x", $2)
	if(length(e) % 2 == 1) {
		e = "0" e
	}
	next
}
$1 ~ /^[0-9a-f][0-9a-f]:/ {
	if(mode > 0) {
		aa = split($1, a, ":")
		for(n = 1; n <= aa; n++) {
			p[mode] = p[mode] a[n]
		}
		next
	}
}
{
	mode = 0
	next
}
END {
	printf("<?php\n  $nx = \"%s\";\n  $ex = \"%s\";\n  $dx = \"%s\";\n  $lx = %d;\n ?>\n",
	       p[1], e, p[2], '$MYKEYLEN')
}
' > keyconf.php
