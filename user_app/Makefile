# Makefile for User-Space Virtual Text Firewall UI
CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -I../driver
TARGET = firewall_ui
SRCS = main.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean