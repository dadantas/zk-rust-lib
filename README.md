# zk-rust-lib

This library provides zero-knowledge proof generation and verification functionalities using the Groth16 proving system. It is written in Rust and can be compiled into a shared library for use in other programming languages, such as Java.

## Prerequisites

- Rust (latest stable version)
- Cargo (Rust package manager)
- Java Development Kit (JDK)

## Building the Library

To build the library, follow these steps:

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd zk-rust-lib
    ```

2. Build the library:
    ```sh
    cargo build --release
    ```

This will generate a shared library (`libzk_rust_lib.so` on Linux, `libzk_rust_lib.dylib` on macOS, or `zk_rust_lib.dll` on Windows) in the `target/release` directory.

## Functions

### `read_zkey`

- **Description**: Reads the proving key and constraint matrices from a file.
- **Parameters**: `path` - Path to the `.arkzkey` file.
- **Returns**: `int` - Status code (0 for success).

### `gen_proof`

- **Description**: Generates a zero-knowledge proof.
- **Parameters**: `inputs` - JSON string of inputs, `wasmPath` - Path to the WASM file.
- **Returns**: `ProofResult` - Contains the proof and its length.

### `verify_proof`

- **Description**: Verifies a zero-knowledge proof.
- **Parameters**: `proofLength` - Length of the proof, `proof` - Byte array of the proof, `pvkPath` - Path to the prepared verifying key file, `publicInputs` - JSON string of public inputs.
- **Returns**: `boolean` - `true` if the proof is valid, `false` otherwise.

### `free_proof`

- **Description**: Frees the memory allocated for the proof.
- **Parameters**: `proof` - The `ProofResult` object to free.

### `free_string`

- **Description**: Frees the memory allocated for a string.
- **Parameters**: `s` - The string to free.
