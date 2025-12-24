CC = gcc

BASE_CFLAGS = -Os -flto -ffunction-sections -fdata-sections \
	-fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
	-fno-ident -fno-stack-clash-protection -fno-exceptions \
	-fno-pic -fno-plt -nostdlib -static -Wall -Wextra -fwhole-program \
	-fno-unroll-loops -fno-tree-vectorize \
	-fno-builtin

CFLAGS = $(BASE_CFLAGS)

ifeq ($(NOAES),1)
  CFLAGS +=
else
  CFLAGS += -maes
endif

LDFLAGS = -Wl,--gc-sections -Wl,--build-id=none -Wl,-n -Wl,--no-eh-frame-hdr \
	-Wl,--hash-style=sysv -s

TARGET = wtf
SRCS = wtf.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@ls -lh $(TARGET)
	@size $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
