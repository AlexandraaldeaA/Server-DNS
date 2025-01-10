CC = g++
CXXFLAGS = -std=c++14 -pthread -g
TARGET = mydns
SRC = client.cpp
INSTALL_PATH = /usr/local/bin

.PHONY: all clean run install

all: clean $(TARGET) install

$(TARGET): $(SRC)
	$(CC) $(CXXFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) $(INSTALL_PATH)

clean:
	rm -f $(TARGET)