from microbit import *
import radio
import random
import music
import speech

#Initialisation des variables du micro:bit
radio.config(group=18, channel=2, address=0x11111111, length=251)
radio.on()
password = "PISSEPENDOUILLE"
sessional_password = ""
nonce_list = set()
baby_state = 0
temp_too_hot = 32
temp_too_cold = 18
can_alert_temp = True
set_volume(100)

image_menu_statut = Image.HAPPY
image_menu_lait = Image.PACMAN
image_menu_temperature = Image('00055:'
                               '99955:'
                               '90000:'
                               '90000:'
                               '99900')
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

images_home = [image_menu_statut, image_menu_lait, image_menu_temperature]
messages_home = ["Check baby's state", "Open milk diary", "Check baby's temperature"]

images_state = [Image.FABULOUS, image_retour]
messages_state = ["Activate sleep mode", "Go back"]

images_lait = [image_regarder, image_history, image_retour]
messages_lait = ["See total consommation", "Chech history", "Go back"]

images_temperature = ["1", "2", image_retour]
messages_temperature = ["Check temperature", "Send temperature to parents", "Go back"]


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
        radio.send(encrypted_packet)
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
    show_and_say(Image.ALL_CLOCKS, "Trying")
    # Génère 4 chiffres aléatoire
    numbers = []
    for _ in range(4):
        numbers.append(str(random.randint(1, 100)))
    # Création du challenge
    challenge = ",".join(numbers)

    # Envoie du challenge crypté
    send_packet(key, "0x01", challenge)
    
    # Calcul le hash de la réponse
    hashed_result = calculate_challenge_response(challenge)
    new_password = str(hashed_result[-3:]) + key

    # Attends la réponse
    for _ in range(200000):
        packet = radio.receive()
        if packet:
            # Unpack du packet
            tlv = unpack_data(packet, new_password)
            # Si bonne réponse
            if tlv[0] == "0x01":
                if hashed_result == tlv[2]:
                    show_and_say(Image.YES, "Connected")
                    return hashed_result, new_password
                show_and_say(Image.NO, "Not good answer")
                return "Incorrect Hash", ""
            show_and_say(Image.NO, "Not good type")
            return "Incorrect Type", ""
    show_and_say(Image.NO, "No response")
    return "No packet received", ""


def show_and_say(image, message):
    """Fonction qui permet d'affiche une image et de prononcer un texte

    Args:
        image (Image): Objet Image
        message (str): Texte qu'il prononcera
    """
    display.show(image, wait=False)
    speech.say(message)

def check_alerte():
    """Vérifie si il y'a des alertes à envoyer"""
    global sessional_password, can_alert_temp, temp_too_cold, temp_too_hot
    
    # Si température trop basse ou élevé
    temp = temperature()
    if temp >= temp_too_hot and can_alert_temp:
        send_packet(sessional_password, "Temp too hot", str(temp))
        can_alert_temp = False
        
    elif temp <= temp_too_cold and can_alert_temp:
        send_packet(sessional_password, "Temp too cold", str(temp))
        can_alert_temp = False
        
    # Si température reviens dans la normal alors on peut renvoyer des alarmes
    elif temp > temp_too_cold+1 and temp < temp_too_hot-1:
        can_alert_temp = True

def handle_packet(packet):
    # Unpack du packet
    show_and_say(Image.ALL_CLOCKS, "Packet received")
    tlv = unpack_data(packet, sessional_password)
            
    # Si c'est une demande pour la temperature
    if tlv[0] == "Ask temperature":
        send_packet(sessional_password, "Give temperature", str(temperature()))
        show_and_say(Image.YES, "Temperature sent")

    # Si demande de l'état du bébé
    if tlv[0] == "Ask state":
        send_packet(sessional_password, "Give state", str(get_state()))
        show_and_say(Image.YES, "State sent")
    
    # Si demande de musique     
    if tlv[0] == "Play musique":
        music.play(['C', 'G', 'E', 'C', 'A', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'B', 'D', 'G', 'A#', 'C#', 'G', 'A', 'C', 'G', 'D', 'C', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'B', 'D', 'G', 'A#', 'C#', 'G', 'A', 'C', 'G', 'D', 'C', 'F#', 'F', 'C', 'E', 'E', 'B', 'D', 'D', 'A', 'C', 'C', 'G', 'B', 'F', 'C', 'E', 'E', 'B', 'D', 'D#', 'A#', 'C#', 'D', 'A', 'C', 'G', 'D', 'C', 'G', 'E', 'C', 'A', 'F#', 'C', 'G', 'E', 'C', 'A', 'F#', 'B', 'D', 'G', 'A#', 'C#', 'G', 'A', 'C', 'G', 'D', 'C', 'F#', 'G', 'G'])

def navigate_through(list_image, list_message):
    """Demande à l'utilisateur de choisir dans le menu et renvoi l'index de son choix

    Args:
        list_image (list): Liste d'objet image
        list_message (list): Liste des phrases à dire

    Returns:
        int: l'index du choix de l'utilisateur
    """
    global sessional_password

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
        
        # Vérifie si il y'a des alertes à envoyer
        check_alerte()
        
        # Si recois un packet
        packet = radio.receive()
        if packet:
            handle_packet(packet)
            index = 0
            show_and_say(list_image[index], list_message[index])
            
    return index

def ask_milk():
    global sessional_password
        
    send_packet(sessional_password, "Ask milk history", "")
        
    # Reception du packet
    for _ in range(100000):
        packet = radio.receive()
        if packet:
            # Unpack du packet
            tlv = unpack_data(packet, sessional_password)
            if tlv[0] == "Give milk history":
                string = tlv[2]
                string = string.replace("[", "")
                string = string.replace("]", "")
                string = string.replace("'", "")
                liste = string.split(", ")
                if liste:
                    if liste[0]:
                        return liste
                    return []
    # Si aucune réponse
    show_and_say(Image.NO, "No response")
    return "BACK"

def baby_milk_menu():
    global milk_history
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
                total += int(element)
        display.scroll(str(total))
    
    while True:
        index = navigate_through(images_lait, messages_lait)
        if index == 0:
            show_consommation(milk_history)
        elif index == 1:
            show_history(milk_history)
        elif index == 2:
            return

def baby_temp_menu():
    global sessional_password
    while True:
        index = navigate_through(images_temperature, messages_temperature)
        # Affiche la temperature
        if index == 0:
            temp = temperature()
            display.scroll(str(temp), wait=False)
            speech.say("The temperature here is " + str(temp) + "degrees Celcius")
        # Envoie la température aux parents
        elif index == 1:
            send_packet(sessional_password, "Give temperature", str(temperature()))
            show_and_say(Image.YES, "Temperature sent")
        # Retourne en arrière
        elif index == 2:
            return

def get_state(number_of_measures=2000, time=4000):
    """Retourne l'état du bébé en fonction de son accélération sur une duréé de 3sec

    Args:
        number_of_measure (int, optional): Nombre de mesure que le microbit  prendra. Defaults to 2000.
        time (int, optional): Période de temps (en ms) sur laquelle le microbit prendra les mesureas. Defaults to 4000.
    """
    # Calcule l'accélération moyenne 
    total_acceleration = 0 
    for _ in range(number_of_measures):
        total_acceleration += abs(int(accelerometer.get_strength() - 1000))
        sleep(time/number_of_measures)
    total_acceleration = total_acceleration //  number_of_measures
    
    if total_acceleration < 75:
        return 0
    elif total_acceleration < 200:
        return 1
    else:
        return 2

def baby_state_menu():
    global sessional_password
    def put_to_sleep():
        show_and_say(Image.YES, "Sleep mode activated")
        display.show(Image('00000:'
                           '33033:'
                           '00000:'
                           '03330:'
                           '00000'))
        # Pendant son sommeil
        radio.off()
        while not (button_a.was_pressed() or button_b.was_pressed()):
            # Mouvement
            state = get_state()
            if state == 2:
                send_packet(sessional_password, "Too agitated", str(state))
            elif state == 1:
                send_packet(sessional_password, "Agitated", str(state))
                    
            # Son
           
        radio.on()
    
    while True:
        index = navigate_through(images_state, messages_state)
        # Activation du mode sommeil
        if index == 0:
            put_to_sleep()
        # Retour en arrière
        elif index == 1:
            return


# Tente un connexion si appuie sur bouton a
display.show("B")
while not sessional_password:
    if button_a.was_pressed():
        hashed_response, sessional_password = establish_connexion(password)

# Boucle principale
while True:
    # Affichage du menu home
    index = navigate_through(images_home, messages_home)
    
    # Si choix = Etat du bébé
    if index == 0:
        baby_state_menu()

    # Si choix = Consommation de lait
    elif index == 1:
        milk_history = ask_milk()
        # Si aucune réponse, retourne en arrière
        if milk_history == "BACK":
            continue
        # Affiche du menu pour le lait
        baby_milk_menu()

    # Si choix = Capteur de température
    elif index == 2:
        baby_temp_menu()