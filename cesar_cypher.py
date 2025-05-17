# This file contains the algorithm for the Cesar cipher.

def cesar_cypher(text, value):
    """
    Encrypt or decrypt a text, getting the relative value of the letters.
    if the value is positive, it encrypts the text
    if the value is negative, it decrypts the text
    """

    result = ""

    # Loop
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        # ord returns the unicode code of the character
        #  -65 is the unicode code of 'A'
        #  %26 is to make the result in the alphabet
        #  +65 is to get the unicode code of the character again
        if char.isupper():
            result += chr((ord(char) + value - 65) % 26 + 65)

        # Encrypt lowercase characters
        #  -97 is the unicode code of 'a'
        #  %26 is to make the result in the alphabet
        #  +97 is to get the unicode code of the character again
        elif char.islower():
            result += chr((ord(char) + value - 97) % 26 + 97)

        # If it's not a char, just add it to the result
        else:
            result += char
    return result

# Usage

if __name__ == "__main__":
    # Example
    text = "Hello World"
    # Change this value to increase or decrease the shift
    value = 3
    print("Text: " + text)
    print("Shift: " + str(value))
    print("Cipher: " + cesar_cypher(text, value))

    encypted = cesar_cypher(text, value)

    # Decrypt
    print("Text: " + text)
    print("Shift: " + str(-value))
    print("Cipher: " + cesar_cypher(encypted, -value))
