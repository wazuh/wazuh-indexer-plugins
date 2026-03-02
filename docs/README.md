# Wazuh Indexer Technical Documentation

This folder contains the technical documentation for the Wazuh Indexer. The documentation is organized into the following guides:

- **Development Guide**: Instructions for building, testing, and packaging the Indexer.
- **Reference Manual**: Detailed information on the Indexer’s architecture, configuration, and usage.

## Requirements

To work with this documentation, you need **mdBook** installed.

- Get the latest `cargo` (hit enter when prompted for a default install)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Install `mdbook` and `mdbook-mermaid`
  ```bash
  cargo install mdbook
  cargo install mdbook-mermaid
  ```

## Usage

- To build the documentation, run:
  ```bash
  ./build.sh
  ```
  The output will be generated in the `book` directory.

- To serve the documentation locally for preview, run:
  ```bash
  ./server.sh
  ```
  The documentation will be available at [http://127.0.0.1:3000](http://127.0.0.1:3000).
