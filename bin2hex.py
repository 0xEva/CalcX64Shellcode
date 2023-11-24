def generate_hex_array(file_path):
    try:
        with open(file_path, 'rb') as file:
            byte_data = file.read()
    except IOError as e:
        print(f"Error reading file: {e}")
        return

    hex_array = ', '.join(f'0x{byte:02x}' for byte in byte_data)

    # Printing in a format suitable for C array initialization
    print(f"unsigned char data[] = {{ {hex_array} }};")


if __name__ == "__main__":
    import sys
    generate_hex_array(sys.argv[1])
