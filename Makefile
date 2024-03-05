CXX = clang++
CXXFLAGS = -Wall -Wextra -g

SERVER_LINKS = -lssl -lcrypto -lpthread -lsqlite3 -lcurl
CLIENT_LINKS = -lssl -lcrypto -lsqlite3 -lcurl

SERVER_SOURCES := $(wildcard src/server/*.cpp)
CLIENT_SOURCES := $(wildcard src/client/*.cpp)
COMMON_SOURCES := $(wildcard src/common/*.cpp)

# Convert common sources into object files
COMMON_OBJS := $(patsubst src/common/%.cpp, build/%.o, $(COMMON_SOURCES))

default: build_directory server client clean_objects

build_directory:
	rm -rf build
	mkdir -p build
	mkdir -p filesystem
	mkdir -p login
	touch filesystem/login.login

server: $(SERVER_SOURCES) $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_LINKS) $^ -o build/etftp_server

client: $(CLIENT_SOURCES) $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_LINKS) $^ -o build/etftp_client

build/%.o: src/common/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean_objects:
	rm build/*.o