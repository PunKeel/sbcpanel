#!/bin/bash
# Get your api key:
APIKEY="Api_Key_Here"
TO="your_email_here"
FROM="email_here"
SUBJECT="Safe Browsing alert"


output=$(/usr/local/sbin/sbcpanel -apikey $APIKEY -db /tmp/sb 2>&1)

[[ 0 = $? ]] && exit 0


echo "$output"
{ echo "New unsafe websites were detected."; echo ""; echo ""; echo "$output"; } \
  | mail -s "$SUBJECT" -r "$FROM" "$TO"
