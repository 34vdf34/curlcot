CC=gcc

EXTRA_WARNINGS = -Wall 

INC=`pkg-config --cflags libxml-2.0`

LIBS = -lcurl -lxml2 -lsqlite3

CFLAGS=-ggdb $(EXTRA_WARNINGS)

BINS=curlcot

all: curlcot

curlcot:	curlcot.c log.c ini.c
	 $(CC) $+ $(CFLAGS) $(INC) $(LIBS) -o $@ -I.

	 
clean:
	rm -rf $(BINS)
	rm *.o
	
