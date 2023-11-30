from microbit import *
import radio
import random
import music
import speech

#Initialisation des variables du micro:bit
radio.config(group=18, channel=2, address=0x11111111, length=251)
radio.on()
connexion_established = False
password = "PISSEPENDOUILLE"
sessional_password = ""
nonce_list = set()
baby_state = 0
#set_volume(100)


def generate_nonce(a=1, b=1000):
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
        #Letters encryption/decryption
        if char.isalpha():
            key_index = i % key_length
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
            key_index = i % key_length
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
    Envoi de données fournies en paramètres
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
        radio.send(encrypted_packet)
    else:
        display.scroll("Error, no nonce available, please restard both be:bi")

#Unpack the packet, check the validity and return the type, length and content
def unpack_data(encrypted_packet, key):
    """
    Déballe et déchiffre les paquets reçus via l'interface radio du micro:bit
    Cette fonction renvoit les différents champs du message passé en paramètre

    :param (str) encrypted_packet: Paquet reçu
           (str) key:              Clé de chiffrement
	:return (srt)type:             Type de paquet
            (int)lenght:           Longueur de la donnée en caractères
            (str) message:         Données reçue
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
        return challenge

#Respond to a connexion request by sending the hash value of the number received
def respond_to_connexion_request(key):
    """
    Réponse au challenge initial de connection avec l'autre micro:bit
    Si il y a une erreur, la valeur de retour est vide

    :param (str) key:                   Clé de chiffrement
	:return (srt) challenge_response:   Réponse au challenge
    """
    # Réception du packet
    while True:
        packet = radio.receive()
        if packet:
            # Unpack du packet
            list_message = unpack_data(packet, key)
            # Si type correspondant
            if list_message[0] == "0x01":
                show_and_say(Image.ALL_CLOCKS, "Trying")
                # Retourne le hash de la réponse et le nouveau mot de passe
                hashed_result = calculate_challenge_response(list_message[2])
                new_password = str(hashed_result[-3:]) + key
                sleep(1000)
                send_packet(new_password, "0x01", hashed_result)
                show_and_say(Image.YES, "Connected")
                return hashed_result, new_password
            return "Incorrect Type", ""

image_plus = Image('00900:'
                   '00900:'
                   '99999:'
                   '00900:'
                   '00900')
image_moins = Image('00000:'
                    '00000:'
                    '99999:'
                    '00000:'
                    '00000')
image_zero = "0"
image_regarder = Image.SURPRISED
image_history = Image('00900:'
                      '00900:'
                      '00999:'
                      '00000:'
                      '00000')
image_retour = Image('00000:'
                     '00009:'
                     '09009:'
                     '99999:'
                     '09000')
image_statut_bebe = Image.HAPPY
image_lait = Image.PACMAN
image_temperature = Image('00055:'
                          '99955:'
                          '90000:'
                          '90000:'
                          '99900')
image_danger = Image('00900:'
                     '00900:'
                     '00900:'
                     '00000:'
                     '00900')

images_home = [image_statut_bebe, image_lait, image_temperature]
messages_home = ["Check baby's state", "Open milk diary", "Check baby's temperature"]

images_lait = [image_plus, image_moins, image_zero, image_regarder, image_history, image_retour]
messages_lait = ["Add new dose of milk", "Remove last dose of milk", "Reset consommation", "See total consommation", "Chech history", "Go back"]

def show_and_say(image, message):
    """Fonction qui permet d'affiche une image et de prononcer un texte

    Args:
        image (Image): Objet Image
        message (str): Texte qu'il prononcera
    """
    display.show(image, wait=False)
    speech.say(message)

def alerte(screen_txt:str, message:str):
    # Tant que pas d'action
    while not (pin_logo.is_touched() or button_a.was_pressed() or button_b.was_pressed()):
        # Affiche et prononce un danger
        display.show(image_danger, wait=False)
        speech.say("WARNING!!, WARNING!!")
        display.clear()
        sleep(500)
        # Affiche le contenu du danger
        display.scroll(screen_txt, wait=False)
        speech.say(message)
        sleep(2000)

def navigate_through(list_image, list_message, sessional_password, milk_history):
    """Demande à l'utilisateur de choisir dans le menu et renvoi l'index de son choix

    Args:
        list_image (list): Liste d'objet image
        list_message (list): Liste des phrases à dire

    Returns:
        int: l'index du choix de l'utilisateur
    """
    # Commence à l'index 0
    index = 0
    show_and_say(list_image[index], list_message[index])
    
    while not pin_logo.is_touched():
        # Vers la gauche si bouton a 
        if button_a.was_pressed():
            index -= 1
            # Si négatif on remet à la fin
            if index == -1:
                index += len(list_image)
            # Si index trop grand, retourne au début
            index %= len(list_image)
            show_and_say(list_image[index], list_message[index])
        # Vers la droite si bouton b
        elif button_b.was_pressed():
            index += 1
            # Si négatif on remet à la fin
            if index == -1:
                index += len(list_image)
            # Si index trop grand, retourne au début
            index %= len(list_image)
            show_and_say(list_image[index], list_message[index])

        # Gère si recois un packet
        packet = radio.receive()
        if packet:
            show_and_say(Image.ALL_CLOCKS, "Packet received")
            # Unpack du packet
            tlv = unpack_data(packet, sessional_password)
            packet = ""
            
            # Si c'est une demande pour le lait
            if tlv[0] == "Ask milk history":
                send_packet(sessional_password, "Give milk history", str(milk_history))
            
            # Si c'est un message de température
            elif tlv[0] == "Give temperature":
                temp = tlv[2]
                display.scroll(temp, wait=False)
                speech.say("The temperature here is " + temp + "degrees Celcius")
            
            # Si alerte temperature
            elif tlv[0] == "Temp too hot":
                temp = tlv[2]
                
            index = 0
            show_and_say(list_image[index], list_message[index])

        
    return index

def add_milk(history):
    """Demande la quantité de lait donné au bébé (en mL), et retourne cette quantité

    Args:
        history (list): Liste de int avec la quantité de lait donné à chaque fois

    Returns:
        list: Historique du lait donné
    """
    milk = 100
    count = 0
    while (not pin_logo.is_touched()) or (count == 0):
        display.scroll(str(milk))
        count = 1
        if button_a.was_pressed():
            milk -= button_a.get_presses()
            if milk < 0:
                milk = 0
        elif button_b.was_pressed():
            milk += button_b.get_presses()
    history.append(milk)
    show_and_say(Image.YES, "You have added " + str(milk) + "mililiter of milk")
    sleep(500)
    return history

def remove_last_milk(history):
    """Supprime la dernière dose de lait ajouté

    Args:
        history (list): Liste de int avec la quantité de lait donné à chaque fois

    Returns:
        list: Historique du lait donné (après avoir retiré la dernière dose)
    """
    if history:
        history.pop()
        show_and_say(Image.YES, "Last milk has been removed")
        sleep(500)
        return history
    else:
        show_and_say(Image.NO, "No history have been recorded")
        sleep(500)

def reset_milk(history):
    history.clear()
    show_and_say(Image.YES, "The history has been reseted")
    sleep(500)
    return history

def show_history(history):
    if history:
        for element in history:
            display.scroll(str(element))
    else:
        show_and_say(Image.NO, "No history have been recorded")
        sleep(500)

def show_consommation(history):
    total = 0
    if history:
        for element in history:
            total += element
    display.scroll(str(total))

def milk_menu(milk_history, sessional_password):
    while True:
        index = navigate_through(images_lait, messages_lait, sessional_password, milk_history)
        if index == 0:
            milk_history = add_milk(milk_history)
        elif index == 1:
            milk_history = remove_last_milk(milk_history)
        elif index == 2:
            milk_history = reset_milk(milk_history)
        elif index == 3:
            show_consommation(milk_history)
        elif index == 4:
            show_history(milk_history)
        elif index == 5:
            return milk_history

def ask_temperature(sessional_password):
    
    send_packet(sessional_password, "Ask temperature", "")
    
    # Reception du packet
    for _ in range(100000):
        packet = radio.receive()
        if packet:
            # Unpack du packet
            tlv = unpack_data(packet, sessional_password)
            if tlv[0] == "Give temperature":
                temp = tlv[2]
                return temp
    
    # Si aucune réponse
    show_and_say(Image.NO, "No response")
    return "BACK"

while not sessional_password:
    display.show("P")
    hashed_response, sessional_password = respond_to_connexion_request(password)

milk_history = []
while True:
    index = navigate_through(images_home, messages_home, sessional_password, milk_history)
    if index == 0:
        display.show(Image.CONFUSED)
        sleep(2000)
        continue
    elif index == 1:
        milk_history = milk_menu(milk_history, sessional_password)
    elif index == 2:
        temp = ask_temperature(sessional_password)
        # Si aucune réponse, retourne en arrière
        if temp == "BACK":
            continue
        display.scroll(str(temp), wait=False)
        speech.say("The temperature of the baby is " + str(temp) + " degrees Celcius")