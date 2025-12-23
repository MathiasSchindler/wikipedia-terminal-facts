CC = gcc
STRIP = strip

CFLAGS = -Os -flto -ffunction-sections -fdata-sections \
         -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
         -fno-ident -fno-stack-clash-protection -fno-exceptions \
         -fno-pic -fno-plt -nostdlib -static -Wall -Wextra -fwhole-program

LDFLAGS = -Wl,--gc-sections -Wl,--build-id=none -Wl,-n -Wl,--no-eh-frame-hdr \
          -Wl,--hash-style=sysv -s

SRCS = wtf.c

TARGET = wtf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@ls -lh $(TARGET)
	@size $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
