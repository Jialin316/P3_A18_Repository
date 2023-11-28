from microbit import *
import radio
import random
import music

#Initialisation des variables du micro:bit
radio.config(group=18, channel=2, address=0x11111111)
connexion_established = False
password = "PISSEPENDOUILLE"
sessional_password = password
nonce_list = set()
baby_state = 0
#set_volume(100)


def generate_nonce(a=1, b=100000):
    if len(nonce_list) != b:
        while True:
            nonce = random.randint(a, b)
            if nonce not in nonce_list:
                nonce_list.add(nonce)
                return nonce
    return 0

def hashing(string):
	"""
	Hachage d'une chaîne de caractères fournie en paramètre.
	Le résultat est une chaîne de caractères.
	Attention : cette technique de hachage n'est pas suffisante (hachage dit cryptographique) pour une utilisation en dehors du cours.

	:param (str) string: la chaîne de caractères à hacher
	:return (str): le résultat du hachage
	"""
	def to_32(value):
		"""
		Fonction interne utilisée par hashing.
		Convertit une valeur en un entier signé de 32 bits.
		Si 'value' est un entier plus grand que 2 ** 31, il sera tronqué.

		:param (int) value: valeur du caractère transformé par la valeur de hachage de cette itération
		:return (int): entier signé de 32 bits représentant 'value'
		"""
		value = value % (2 ** 32)
		if value >= 2**31:
			value = value - 2 ** 32
		value = int(value)
		return value

	if string:
		x = ord(string[0]) << 7
		m = 1000003
		for c in string:
			x = to_32((x*m) ^ ord(c))
		x ^= len(string)
		if x == -1:
			x = -2
		return str(x)
	return ""

def vigenere(message, key, decryption=False):
    text = ""
    key_length = len(key)
    key_as_int = [ord(k) for k in key]

    for i, char in enumerate(str(message)):
        key_index = i % key_length
        #Letters encryption/decryption
        if char.isalpha():
            if decryption:
                modified_char = chr((ord(char.upper()) - key_as_int[key_index] + 26) % 26 + ord('A'))
            else : 
                modified_char = chr((ord(char.upper()) + key_as_int[key_index] - 26) % 26 + ord('A'))
            #Put back in lower case if it was
            if char.islower():
                modified_char = modified_char.lower()
            text += modified_char
        #Digits encryption/decryption
        elif char.isdigit():
            if decryption:
                modified_char = str((int(char) - key_as_int[key_index]) % 10)
            else:  
                modified_char = str((int(char) + key_as_int[key_index]) % 10)
            text += modified_char
        else:
            text += char
    return text

#Encrypt and send a message of TLV type
def send_packet(key, type, content):
    """
    Envoie de données fournie en paramètres
    Cette fonction permet de construire, de chiffrer puis d'envoyer un paquet via l'interface radio du micro:bit

    :param (str) key:       Clé de chiffrement
           (str) type:      Type du paquet à envoyer
           (str) content:   Données à envoyer
	:return none
    """
    # Chiffrement des données par vigenère
    nonce = generate_nonce()
    if nonce:
        nonce_c = vigenere(nonce, key)
        lenght_c = vigenere(len(content), key)
        type_c = vigenere(type, key)
        content_c = vigenere(content, key)
        
        # Envoie du packet
        encrypted_packet = type_c + "|" + lenght_c + "|" + nonce_c + ":" + content_c
        radio.on()
        radio.send(encrypted_packet)
        radio.off()
    else:
        print("Error, no nonce available, please restard both be:bi")

#Decrypt and unpack the packet received and return the fields value
def unpack_data(encrypted_packet, key):
    """
    Déballe et déchiffre les paquets reçus via l'interface radio du micro:bit
    Cette fonction renvoit les différents champs du message passé en paramètre

    :param (str) encrypted_packet: Paquet reçu
           (str) key:              Clé de chiffrement
	:return (srt)type:             Type de paquet
            (int)lenght:           Longueur de la donnée en caractères
            (str) message:         Données reçues
    """
    try:
        encrypted_packet = encrypted_packet.split("|")
        type = vigenere(encrypted_packet[0], key, True)
        lenght = vigenere(encrypted_packet[1], key, True)
        message = encrypted_packet[2].split(":")
        content = vigenere(message[1], key, True)
        
        nonce = vigenere(message[0], key, True)
        # Vérifie si le nonce est unique, sinon retourne Erreur
        if nonce not in nonce_list:
            nonce_list.add(nonce)
            return [type, lenght, content]
        else:
            return ["Nonce Error", "", "Same nonce detected"]
    except:
        return ["Unpacking Error", "", "Couldn't unpack the packet received"]

#Calculate the challenge response
def calculate_challenge_response(challenge):
    """
    Calcule la réponse au challenge initial de connection avec l'autre micro:bit
    
    Avec une liste de 4 chiffres, additionne les deux premiers chiffres, 
    soustrait les deux dernier chiffre, puis multiplie les deux chiffres obtenu puis hash le résultat

    :param (str) challenge:            Challenge reçu
	:return (srt)challenge_response:   Réponse au challenge
    """
    try:
        numbers = challenge.split(",")
        a = int(numbers[0]) + int(numbers[1])
        b = int(numbers[2]) - int(numbers[3])
        result = str(a * b)
        return hashing(result)
    except:
        return "Couldn't calculate the response. The format received is incorrect"

#Ask for a new connection with a micro:bit of the same group
def establish_connexion(key):
    """
    Etablissement de la connexion avec l'autre micro:bit
    Si il y a une erreur, la valeur de retour est vide
    Génère une série de 4 chiffres séparé par | et envoie cette série chiffré à l'autre be:bi

    :param (str) key:                  Clé de chiffrement
	:return (srt)challenge_response:   Réponse au challenge
    """
    # Génère 4 chiffres aléatoire
    numbers = []
    for _ in range(4):
        numbers.append(str(random.randint(1, 100)))
    # Création du challenge
    challenge = ",".join(numbers)

    # Envoie du challenge crypté
    send_packet(key, "0x01", challenge)
    
    # Retourne le hash de la réponse
    hashed_result = calculate_challenge_response(challenge)
    new_password = str(hashed_result[-3:]) + key

    # Attends la réponse
    radio.on()
    for _ in range(300000):
        packet = radio.receive()
        if packet:
            # Unpack du packet
            list_message = unpack_data(packet, new_password)
            # Si bonne réponse
            if list_message[0] == "0x01":
                if hashed_result == list_message[2]:
                    return hashed_result, new_password
                return "Incorrect Hash", ""
            return "Incorrect Type", ""
    return "No packet received", ""


while True:
    if button_a.was_pressed():
        response, sessional_password = establish_connexion(password)
        display.scroll(response + sessional_password)