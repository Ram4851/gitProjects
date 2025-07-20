# Convert to positive binary number in 8 bits
def decimal_to_binary_8bit_positive(n):
    bits = [0, 0, 0, 0, 0, 0, 0, 0]  # List to store binary number in 8 bits
    index = 7  # Start from the end of the list (last index)
    while n > 0 and index >= 0:
        bits[index] = n % 2  # Store remainder (0 or 1)
        n = n // 2
        index -= 1
    return bits

# Function to invert bits (0 to 1 and 1 to 0)
def invert_bits(bits):
    inverted = [0] * 8
    for i in range(8):
        inverted[i] = 1 - bits[i]
    return inverted

# Function to add 1 to bits (Two's complement)
def add_one(bits):
    result = bits[:]
    carry = 1
    i = 7
    while i >= 0 and carry == 1:
        if result[i] == 1:
            result[i] = 0
        else:
            result[i] = 1
            carry = 0
        i -= 1
    return result

# Convert decimal number to 8-bit binary (handles positive and negative)
def decimal_to_binary_8bit(n):
    if n >= 0:
        return decimal_to_binary_8bit_positive(n)
    else:
        abs_bits = decimal_to_binary_8bit_positive(-n)
        inverted = invert_bits(abs_bits)
        return add_one(inverted)

# Function to print binary number
def print_bits(bits):
    print(''.join(str(bit) for bit in bits))

# Main function
def main():
    print("Convert a number to 8-bit binary representation")
    n = int(input("Enter a decimal number between -128 and 127: "))
    if n < -128 or n > 127:
        print("The number is out of 8-bit range.")
        return
    bits = decimal_to_binary_8bit(n)
    print("The 8-bit binary representation is:")
    print_bits(bits)

main()
