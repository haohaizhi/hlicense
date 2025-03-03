# Author:hongqiang
# 
.PHONY: all clean rebuild libhlic

target := hlicense_client
shared_lib_target := libhlic.so
CC := g++
RM := rm -rf
CP := cp -rf
TYPE_SRC := .cpp

SRCS := $(wildcard *$(TYPE_SRC))

CFLAGS := -std=c++11 -lssl -lcrypto -Wall
SHARED_CFLAGS := $(CFLAGS) -fPIC -shared

all: $(target)
	@echo "Compile succeed"

$(target): $(SRCS)
	@echo "Compile executable $@"
	$(CC) $^ -o $@ $(CFLAGS)

libhlic: $(SRCS)
	@echo "Compile shared library $@"
	$(CC) $^ -o $(shared_lib_target) $(SHARED_CFLAGS)

clean:
	$(RM) $(target) $(shared_lib_target)

rebuild: clean all
	@echo "Rebuild succeed."
