
if [ -z "${ETFTP_ROOT}" ]; then
    echo "ETFTP_ROOT is not set"
    exit 1
fi

current_directory=$(pwd)

cd $ETFTP_ROOT
rm -rf build
mkdir build
mkdir filesystem >/dev/null 2>&1
mkdir login >/dev/null 2>&1
touch filesystem/login.login

cd src

common_files=$(ls common/*cpp)
server_files=$(ls server/*.cpp)
client_files=$(ls client/*.cpp)

clang++ -Wall -Wextra -g -lssl -lcrypto -lpthread -lsqlite3 -lcurl -o ../build/etftp_server $common_files $server_files

cd $current_directory