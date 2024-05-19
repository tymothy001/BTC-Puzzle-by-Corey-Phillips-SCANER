from bip_utils import Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages, Bip84, Bip84Coins, Bip44Changes
from tqdm import tqdm
import os
def print_logo():
    logo = """

██████╗ ████████╗ ██████╗    ██████╗ ██╗   ██╗███████╗███████╗██╗     ███████╗
██╔══██╗╚══██╔══╝██╔════╝    ██╔══██╗██║   ██║╚══███╔╝╚══███╔╝██║     ██╔════╝
██████╔╝   ██║   ██║         ██████╔╝██║   ██║  ███╔╝   ███╔╝ ██║     █████╗
██╔══██╗   ██║   ██║         ██╔═══╝ ██║   ██║ ███╔╝   ███╔╝  ██║     ██╔══╝
██████╔╝   ██║   ╚██████╗    ██║     ╚██████╔╝███████╗███████╗███████╗███████╗
╚═════╝    ╚═╝    ╚═════╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝
====================================================================================
  BTC Puzzle by Corey Phillips SCANER HD KEY V.O1

  Turn Your Photos Into Bitcoin Private Keys/Addresses

  usage: python3 BIP84generatorBip39.py


  donate: 1xxxxe1QUbmLATePu2AKBCm2jAfVtx2jy

====================================================================================
    """
    print(logo)

if __name__ == '__main__':
    print_logo()
# Funkcja do wczytania haseł z pliku
def read_passwords_from_file(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]

# Funkcja do generowania kluczy HD i adresów
def generate_hd_keys_and_addresses(mnemonic, passwords, num_addresses, output_file):
    # Walidacja mnemonic z określonym językiem
    validator = Bip39MnemonicValidator(lang=Bip39Languages.ENGLISH)
    validator.Validate(mnemonic)

    with open(output_file, "w") as file:
        # Użycie tqdm do stworzenia paska postępu
        for password in tqdm(passwords, desc="Processing passwords"):
            # Generowanie seed z mnemonic i hasła
            seed_bytes = Bip39SeedGenerator(mnemonic).Generate(password)

            # Tworzenie portfela BIP84
            bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

            # Zapis BIP32 Root Key do pliku
            bip32_root_key = bip84_ctx.PrivateKey().ToExtended()
            file.write(f"BIP32 Root Key (password: {password}): {bip32_root_key}\n")

            # Iteracja po indeksach adresów
            for i in range(num_addresses):
                # Generowanie ścieżki m/84'/0'/0'/0/i
                bip84_addr_ctx = bip84_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                # Zapis klucza i adresu do pliku
                file.write(f"Address {i}: {bip84_addr_ctx.PublicKey().ToAddress()}\n")
                file.write(f"HD Key {i}: {bip84_addr_ctx.PrivateKey().Raw().ToHex()}\n\n")
            file.write("\n")

# Główna część programu
if __name__ == "__main__":
    mnemonic = "elite usual surround kiwi angry aerobic force public awake divide yellow foot remove cycle obvious seven business sister fortune coach oppose forest dish detail"
    password_file = "english.txt"
    output_file = "HDkey.txt"
    num_addresses = 25

    # Wczytanie haseł z pliku
    passwords = read_passwords_from_file(password_file)

    # Generowanie kluczy HD i adresów
    generate_hd_keys_and_addresses(mnemonic, passwords, num_addresses, output_file)

    print(f"Generated HD keys and addresses for all passwords and saved to {output_file}")
