CC = g++
TARGET = MasterServer
SRC = MasterServer.cpp
MYDNS_SCRIPT = mydns
INSTALL_PATH = /usr/local/bin

.PHONY: all clean

all: $(TARGET) stop install start

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC)

stop:
	sudo systemctl stop systemd-resolved

install:
	@if [ -f $(MYDNS_SCRIPT) ]; then \
		chmod +x $(MYDNS_SCRIPT); \
		sudo mv $(MYDNS_SCRIPT) $(INSTALL_PATH); \
	fi
start:
	sudo ./$(TARGET)
clean:
	rm -f $(TARGET)
