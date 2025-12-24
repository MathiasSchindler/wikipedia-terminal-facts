# Wikipedia Terminal Facts (wtf)

`wtf` is a standalone terminal program that fetches a short summary from Wikipedia and prints it to stdout.

Size note: the project is optimized for a tiny statically-linked binary, with a rough target around **~16 KiB** (exact size varies by toolchain/flags).

It’s built to be minimal:

- single C file
- static ELF
- no libc (direct Linux syscalls)
- minimal TLS 1.3 client implementation (X25519 + AES-128-GCM)

## What it does

- Turns your command-line query into a Wikipedia page title
- Requests the Wikipedia REST API summary endpoint
- Extracts and prints the `extract` field (a plain-text summary)

If the summary endpoint returns 404, it falls back to the MediaWiki OpenSearch API to find a close match and tries again.

## Requirements

- Linux x86-64
- IPv6 connectivity (the resolver is AAAA-only)
- A CPU/toolchain that can build AES-NI by default (see `NOAES=1` below)
- `gcc` and GNU `make`

## Build

- Default build:
  - `make`

- Build without AES-NI (disables `-maes` in `Makefile`):
  - `make clean && make NOAES=1`

The produced binary is a statically linked, stripped ELF.

## Usage

- Basic query:
  - `./wtf "alan turing"`

- Specify language (Wikipedia subdomain):
  - `./wtf -l de Berlin`

The program prints the summary text to stdout and appends a newline if needed.

## Examples

### English (default)

```sh
./wtf Caffeine
```

Example output:

```
Caffeine is a central nervous system (CNS) stimulant of the methylxanthine class and is the most commonly consumed psychoactive substance globally. It is mainly used for its eugeroic, ergogenic, or nootropic (cognitive-enhancing) properties; it is also used recreationally or in social settings. Caffeine acts by blocking the binding of adenosine at a number of adenosine receptor types, inhibiting the centrally depressant effects of adenosine and enhancing the release of acetylcholine. Caffeine has a three-dimensional structure similar to that of adenosine, which allows it to bind and block its receptors. Caffeine also increases cyclic AMP levels through nonselective inhibition of phosphodiesterase, increases calcium release from intracellular stores, and antagonizes GABA receptors, although these mechanisms typically occur at concentrations beyond usual human consumption.
```

### German via `-l`

```sh
./wtf -l de Schwarzstart
```

Example output:

```
Als Schwarzstart wird das Anfahren eines Kraftwerks(blocks) bezeichnet, wenn dies unabhängig vom Stromnetz geschieht. Unter Schwarzstartfähigkeit versteht man die Fähigkeit eines Kraftwerks(blocks), unabhängig vom Stromnetz vom abgeschalteten Zustand ausgehend hochzufahren.
```

## How it works (high-level)

1. **Query formatting**
   - CLI args are joined into a single title-ish string (spaces become underscores).

2. **DNS (hardcoded resolver)**
   - Uses a hardcoded Google IPv6 DNS server (`2001:4860:4860::8888`).
   - Sends a UDP DNS query for an AAAA record.
   - No TCP fallback.

3. **TCP + TLS 1.3**
   - Connects to the resolved IPv6 address on port 443.
   - Performs a minimal TLS 1.3 handshake:
     - X25519 key exchange
     - HKDF/SHA-256 key schedule
     - AES-128-GCM record protection
   - Verifies the server Finished message.

4. **HTTP/1.1 request**
   - Sends a small `GET` request with `Host` and `Connection: close`.

5. **HTTP response parsing**
   - Finds the `\r\n\r\n` header/body separator.
   - Supports `Transfer-Encoding: chunked`.

6. **JSON extraction**
   - For the summary endpoint, extracts the `extract` string.
   - If summary returns 404, uses OpenSearch and retries.

## Design notes / limitations

- **Not a general-purpose TLS stack.** This is a purpose-built, minimal client.
- **IPv6-only path.** DNS is AAAA-only; there’s no IPv4 A-record resolver.
- **Hardcoded DNS.** No `/etc/resolv.conf` parsing.
- **Minimal HTTP parsing.** Only what’s needed for Wikipedia APIs.

## License (CC0)

This project is released under **CC0 1.0 Universal (CC0)**.

- https://creativecommons.org/publicdomain/zero/1.0/

## AI assistance / provenance

Parts of this project were developed using prompting to large language models, including **Anthropic Claude Opus 4.5** and **OpenAI GPT-5.2**.
