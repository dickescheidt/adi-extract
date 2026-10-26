# POSIX build of adi-extract (Linux, macOS, *BSD).
# On Windows use the upstream CMakeLists.txt / build.ps1 with MSVC instead.
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS  ?=
SRC      := $(wildcard src/*.cpp)
OBJ      := $(SRC:.cpp=.o)

all: adi-extract

adi-extract: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -Isrc -c -o $@ $<

clean:
	rm -f $(OBJ) adi-extract

.PHONY: all clean
