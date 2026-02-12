# plume

A tool to sign and verify files using Nostr. Think GPG, but user-friendly.

## Installation

### PyPI

```sh
pip install plume-nostr
```

### Source

```sh
git clone https://github.com/f321x/plume
cd plume
pip install -e .
```

## Usage

### GUI

```sh
plume
```

### CLI

#### Sign

```sh
plume-cli sign file.txt --key nsec1...
```

#### Verify

```sh
plume-cli verify file.txt
```

#### Config

```sh
plume-cli config --list
plume-cli config --add-relay wss://relay.damus.io
plume-cli config --add-trusted npub1...
```
