CC = g++
CXXFLAGS = -std=c++14 -lpthread -I./ -I./include

TARGET = MasterServer
SRC = MasterServer.cpp ThreadPool.cpp
INSTALL_PATH = /usr/local/bin

.PHONY: all clean run

all: $(TARGET) stop run

$(TARGET): $(SRC)
	$(CC) $(CXXFLAGS) -o $(TARGET) $(SRC)

stop:
	sudo systemctl stop systemd-resolved

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)