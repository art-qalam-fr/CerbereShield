for
/f
tokens=5
%%a
in
netstat -aon ^^| find "4050" ^^| find "LISTENING"
do
echo
%%a
