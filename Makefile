CC = gcc
STRIP = strip

CFLAGS = -Os -flto -ffunction-sections -fdata-sections \
         -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
         -fno-ident -fno-stack-clash-protection -fno-exceptions \
         -fno-pic -fno-plt -nostdlib -static -Wall -Wextra -maes -fwhole-program

LDFLAGS = -Wl,--gc-sections -Wl,--build-id=none -Wl,-n -Wl,--no-eh-frame-hdr \
          -Wl,--hash-style=sysv -s

SRCS = mc_aes.c mc_gcm.c mc_hkdf.c mc_hmac.c mc_io.c mc_libc_compat.c \
       mc_mathf.c mc_sha256.c mc_start.c mc_start_env.c mc_str.c \
       mc_tls13.c mc_tls13_client.c mc_tls13_handshake.c mc_tls13_transcript.c \
       mc_tls_record.c mc_x25519.c wtf.c

TARGET = wtf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@ls -lh $(TARGET)
	@size $(TARGET)

clean:
	rm -f $(TARGET)

smoke: $(TARGET)
	./$(TARGET) --smoke

.PHONY: all clean smoke
