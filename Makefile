# POSIX build of adi-extract (Linux, macOS, *BSD).
# On Windows use the upstream CMakeLists.txt / build.ps1 with MSVC instead.
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS  ?=
SRC      := $(wildcard src/*.cpp)
OBJ      := $(SRC:.cpp=.o)
DEP      := $(OBJ:.o=.d)

all: adi-extract

adi-extract: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -Isrc -c -o $@ $<

# Rebuild when a header changes (text.hpp / win32_shim.hpp are included by
# several translation units; without -MMD a stale object silently survives).
-include $(DEP)

test: adi-extract
	./tests/test-multipart.sh
	./tests/test-safety.sh

clean:
	rm -f $(OBJ) $(DEP) adi-extract

.PHONY: all clean test
