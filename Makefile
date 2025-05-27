CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread
TARGET = port_scanner
SOURCE = simple_scanner.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

.PHONY: all clean install 