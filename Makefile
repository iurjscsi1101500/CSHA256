CXX = gcc
CXXFLAGS = -O3 -std=c11
TARGET = test
SRC = test.c
all: $(TARGET)
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
clean:
	rm -f $(TARGET)
.PHONY: all clean

