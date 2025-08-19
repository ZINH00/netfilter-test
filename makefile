CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDLIBS   := -lnetfilter_queue -lmnl -lnet

TARGET := netfilter-test

all: $(TARGET)

$(TARGET): main.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o

