# Author:hongqiang
# 

.phony: all clean rebuild

target := hlicense_server
CC := g++
RM := rm -rf
CP := cp -rf
TYPE_SRC := .cpp

SRCS := $(wildcard *$(TYPE_SRC))
	
CFLAGS := -std=c++11 -lssl -lcrypto -Wall


all:$(target) 
	@echo "complie succeed"
	
$(target):$(SRCS)
	@echo "complie $@" 
	$(CC) $^ -o $@ $(CFLAGS) 

clean:
	$(RM) $(target)
rebuild: clean all
	@echo "rebuild succeed."
