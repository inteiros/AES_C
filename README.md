# Simple AES Encryption/Decryption Example

This example demonstrates the basic usage of OpenSSL's AES encryption and decryption capabilities in CBC mode. It provides a straightforward implementation that includes error handling, timing of encryption and decryption processes, and output handling of encrypted data in both binary and hexadecimal format.

## Features

- AES encryption and decryption using OpenSSL.
- Error handling with detailed OpenSSL error messages.
- Performance timing for encryption and decryption operations.
- Reading encrypted data from a file for decryption.
- Demonstrates the use of AES-128 for encryption and AES-256 for decryption (note: this is for educational purposes; ensure algorithm and key size match in production use).

## Prerequisites

- OpenSSL library must be installed on your system.
- A C compiler (such as GCC) is required to compile the program.
- This code is designed for Unix-like operating systems. Adjustments may be necessary for other environments.

## Compilation

The program needs to be linked with OpenSSL libraries (`libssl` and `libcrypto`). Here's how you can compile it:

```sh
gcc -o AES.c -lssl -lcrypto
```

## Running the Program

Execute the compiled program with:

```sh
./AES
```

Upon execution, the program performs the following steps:

1. **Encryption**: Encrypts a predefined plaintext string using AES-128-CBC mode.
2. **Ciphertext output**: Displays the encrypted data in both ASCII and hexadecimal format.
3. **Decryption**: Reads encrypted data from a file named `1111.bin`, then decrypts it using AES-256-CBC mode.
4. **Decrypted text output**: Displays the decrypted text, verifying the success of the decryption process.
5. **Timing information**: Presents the time taken for both encryption and decryption in microseconds.


## License

This example is provided for educational purposes and is not covered by any specific license.