# Перестановки та таблиці заміни для S-DES
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8  = [6, 3, 7, 4, 8, 5, 10, 9]

IP  = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP  = [4, 1, 2, 3, 2, 3, 4, 1]
P4  = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

def permute(bits: str, table: list) -> str:
    """Виконує перестановку бітів за вказаною таблицею (індексація з 1)."""
    return "".join(bits[idx - 1] for idx in table)

def left_shift(bits: str, n: int = 1) -> str:
    """Циклічний зсув вліво на n позицій."""
    return bits[n:] + bits[:n]

def xor(bits1: str, bits2: str) -> str:
    """Побітова операція XOR для двох бінарних рядків."""
    return "".join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

def generate_keys(key_10bit: str) -> tuple[str, str]:
    """Генерація підключів K1 та K2 з 10-бітного ключа."""
    p10 = permute(key_10bit, P10)
    left, right = p10[:5], p10[5:]

    left_ls1, right_ls1 = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(left_ls1 + right_ls1, P8)

    left_ls2, right_ls2 = left_shift(left_ls1, 2), left_shift(right_ls1, 2)
    k2 = permute(left_ls2 + right_ls2, P8)

    return k1, k2

def s_box(bits4: str, s_table: list) -> str:
    """Обробка 4 бітів у S-блоці (ряд: 1-й і 4-й біт, стовпець: 2-й і 3-й біт)."""
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    val = s_table[row][col]
    return f"{val:02b}"

def f_k(bits8: str, key8: str) -> str:
    """Фейстелівська функція fk."""
    left, right = bits8[:4], bits8[4:]
    ep = permute(right, EP)
    xored = xor(ep, key8)
    s0_out = s_box(xored[:4], S0)
    s1_out = s_box(xored[4:], S1)
    p4 = permute(s0_out + s1_out, P4)
    
    return xor(left, p4) + right

def encrypt_block(block8: str, k1: str, k2: str) -> str:
    """Шифрування одного 8-бітного блоку."""
    ip = permute(block8, IP)
    fk1 = f_k(ip, k1)
    swapped = fk1[4:] + fk1[:4]  # Switch (SW)
    fk2 = f_k(swapped, k2)
    return permute(fk2, IP_INV)

def decrypt_block(block8: str, k1: str, k2: str) -> str:
    """Розшифрування одного 8-бітного блоку (використовує ключі K2, потім K1)."""
    return encrypt_block(block8, k2, k1)

def text_to_bits(text: str) -> list[str]:
    """Перетворює текст у список 8-бітних рядків."""
    return [f"{byte:08b}" for byte in text.encode("utf-8")]

def bits_to_text(bits_list: list[str]) -> str:
    """Перетворює список 8-бітних рядків назад у текст."""
    data = bytes(int(b, 2) for b in bits_list)
    return data.decode("utf-8")


def main():
    print("=== Спрощений алгоритм шифрування S-DES ===")
    
    key_input = input("Введіть 10-бітний ключ (наприклад, 1010000010): ").strip()
    if len(key_input) != 10 or not all(c in '01' for c in key_input):
        print("Помилка: Ключ мусить складатися рівно з 10 бітів (0 та 1)!")
        return

    k1, k2 = generate_keys(key_input)
    print(f"Згенеровані підключі: K1 = {k1}, K2 = {k2}\n")

    print("Оберіть режим:")
    print("1. Шифрування/Розшифрування 8-бітного блоку (наприклад, 11010111)")
    print("2. Шифрування/Розшифрування тексту")
    mode = input("Ваш вибір (1 або 2): ").strip()

    if mode == '1':
        block = input("Введіть 8-бітне повідомлення: ").strip()
        if len(block) != 8 or not all(c in '01' for c in block):
            print("Помилка: Блок мусить містити 8 бітів!")
            return
            
        cipher_block = encrypt_block(block, k1, k2)
        decrypted_block = decrypt_block(cipher_block, k1, k2)
        
        print(f"\nВхідний блок:    {block}")
        print(f"Зашифровано:     {cipher_block}")
        print(f"Розшифровано:    {decrypted_block}")

    elif mode == '2':
        text = input("Введіть текст для шифрування: ")
        bits_list = text_to_bits(text)
        encrypted_bits = [encrypt_block(b, k1, k2) for b in bits_list]
        decrypted_bits = [decrypt_block(b, k1, k2) for b in encrypted_bits]
        cipher_hex = "".join(f"{int(b, 2):02X}" for b in encrypted_bits)
        restored_text = bits_to_text(decrypted_bits)
        print(f"\nЗашифрований текст (HEX): {cipher_hex}")
        print(f"Відновлений текст: {restored_text}")
    else:
        print("Невірний вибір!")

if __name__ == "__main__":
    main()