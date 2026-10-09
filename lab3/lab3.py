import math

# Алфавіти для роботи
UKRAINIAN_ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def mod_inverse(a: int, m: int) -> int:
    """Обчислює мультиплікативне обернене значення a mod m за допомогою розширеного алгоритму Евкліда."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"Число a={a} не має оберненого за модулем m={m}.")

def process_text(text: str, a: int, b: int, mode: str = 'encrypt', alphabet: str = UKRAINIAN_ALPHABET) -> str:
    """
    Шифрує або розшифровує текст за допомогою афінного шифру.
    
    :param text: Вхідний текст
    :param a: Параметр ключа 'a' (мусить бути взаємно простим із len(alphabet))
    :param b: Параметр ключа 'b'
    :param mode: 'encrypt' або 'decrypt'
    :param alphabet: Набір символів для шифрування
    """
    m = len(alphabet)
    
    if math.gcd(a, m) != 1:
        raise ValueError(f"Параметр 'a' ({a}) та розмір алфавіту 'm' ({m}) повинні бути взаємно простими! НСД({a}, {m}) != 1")
    
    result = []
    
    if mode == 'decrypt':
        a_inv = mod_inverse(a, m)
    
    for char in text:
        is_upper = char.isupper()
        char_upper = char.upper()
        
        if char_upper in alphabet:
            x = alphabet.index(char_upper)
            if mode == 'encrypt':
                y = (a * x + b) % m
            else:  # decrypt
                y = (a_inv * (x - b)) % m
            
            new_char = alphabet[y]
            result.append(new_char if is_upper else new_char.lower())
        else:
            result.append(char)
            
    return "".join(result)

def main():
    print("=== Афінна система шифрування Цезаря ===")
    print("1. Зашифрувати файл")
    print("2. Розшифрувати файл")
    
    choice = input("Оберіть дію (1 або 2): ").strip()
    if choice not in ['1', '2']:
        print("Невірний вибір!")
        return

    print("\nОберіть алфавіт:")
    print("1. Український (33 символи)")
    print("2. Англійський (26 символів)")
    alph_choice = input("Ваш вибір (1 або 2): ").strip()
    
    if alph_choice == '1':
        alphabet = UKRAINIAN_ALPHABET
    elif alph_choice == '2':
        alphabet = ENGLISH_ALPHABET
    else:
        print("Невірний вибір алфавіту!")
        return

    m = len(alphabet)
    print(f"Розмір обраного алфавіту (m) = {m}")

    mode = 'encrypt' if choice == '1' else 'decrypt'

    # Налаштування значень за замовчуванням
    default_input = "input.txt"
    default_output = "output.txt" 

    input_file = input(f"Введіть шлях до вхідного файлу (за замовчуванням '{default_input}'): ").strip()
    if not input_file:
        input_file = default_input

    output_file = input(f"Введіть шлях для збереження результату (за замовчуванням '{default_output}'): ").strip()
    if not output_file:
        output_file = default_output

    try:
        a = int(input(f"Введіть параметр a (повинен бути взаємно простим із {m}): "))
        b = int(input(f"Введіть параметр b (0 <= b < {m}): "))
    except ValueError:
        print("Помилка: параметри ключа повинні бути цілими числами!")
        return

    try:
        # Виправлено: читаємо файл без передачі порожнього рядка
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        processed_content = process_text(content, a, b, mode=mode, alphabet=alphabet)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(processed_content)

        action_name = "зашифровано" if mode == 'encrypt' else "розшифровано"
        print(f"\nУспішно! Файл {action_name} та збережено у '{output_file}'.")

    except FileNotFoundError:
        print(f"Помилка: Файл '{input_file}' не знайдено.")
    except Exception as e:
        print(f"Помилка під час виконання: {e}")

if __name__ == "__main__":
    main()