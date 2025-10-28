APP = funclatency
BPF_OBJ = $(APP).bpf.o
SKELETON = $(APP).skel.h
USER_SRC = $(APP).cpp # Source is now a .cpp file
USER_OBJ = $(APP).o

# Using dynamic linking for simplicity.
# For a static binary, use: LDFLAGS = -static -lbpf -lelf -lz
LDFLAGS = -lbpf -lelf -lz -static

# Compiler and flags
CXX = g++
CLANG = clang
CXXFLAGS = -g -Wall -std=c++17
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86

all: $(APP)

$(SKELETON): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): $(APP).bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $(APP).bpf.c -o $@

$(USER_OBJ): $(USER_SRC) $(SKELETON)
	$(CXX) $(CXXFLAGS) -c $(USER_SRC) -o $@

$(APP): $(USER_OBJ) $(BPF_OBJ)
	$(CXX) $(CXXFLAGS) $(USER_OBJ) $(LDFLAGS) -o $@

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKELETON) $(USER_OBJ)