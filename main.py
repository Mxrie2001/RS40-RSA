# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""

import hashlib
import binascii
import random
import math
import secrets

def home_mod_expnoent(x, y, n):  # exponentiation modulaire
    # Convertir y en binaire et stocker chaque bit dans une liste
    tab = []
    binaireY = bin(y) # convertir en binaire
    binaireY = binaireY[2::] # supprimer le '0b' au début

    # ajouter chaque bit de y à la liste tab
    for i in range(len(binaireY)):
        tab.append(binaireY[i])

    # renverser la liste tab pour lire les bits dans le bon ordre
    tab.reverse()

    # initialiser r1 et r2
    r1 = 1
    r2 = x

    # Parcourir les bits de y
    for i in range(0, len(tab)):
        if tab[i] == str(1): # si le bit est égal à 1
            r1 = (r1 * r2) % n # calculer r1
        r2 = (r2 ** 2) % n # calculer r2

    return r1 # renvoyer le résultat final


def home_ext_euclide(y, b):
    # Initialisation de variables et listes
    q = []
    u = [1, 0]
    nouvr = y
    r = b

    # Boucle qui calcule le pgcd et les coefficients de Bézout
    while nouvr:
        # Effectue une division euclidienne pour obtenir le quotient et le reste
        quotient, nouvr, r = r // nouvr, r % nouvr, nouvr
        # Calcule les coefficients de Bézout
        u.append(u[-2] - quotient * u[-1])
        # Stocke le quotient
        q.append(quotient)

    # Calcul du résultat final
    return u[-2] % y






def calculPréalable(xi, xj, d):
    # Initialisation de la variable n
    n = xi * xj

    # Si xi est inférieur à xj, q prend la valeur de xi et p prend la valeur de xj
    # Sinon, q prend la valeur de xj et p prend la valeur de xi
    if (xi < xj):
        q = xi
        p = xj
    else:
        q = xj
        p = xi
    # Appel de la fonction home_ext_euclide avec les arguments p et q
    qPrime = home_ext_euclide(p, q)

    # Calcul du reste de la division de d par q-1 et p-1, respectivement
    dq = d % (q - 1)
    dp = d % (p - 1)

    return (qPrime, dq, dp, q, p, n)


def CRT(xi, xj, d, message):
    # Appel de la fonction calculPréalable pour déterminer les valeurs de qPrime, dq, dp, q, p et n
    (qPrime, dq, dp, q, p, n) = calculPréalable(xi, xj, d)

    # Calcul de mq et mp en utilisant la fonction home_mod_expnoent
    mq = home_mod_expnoent(message, dq, q)
    mp = home_mod_expnoent(message, dp, p)

    # Calcul de la variable h comme le reste de la division de ((mp-mq) multiplié par qPrime) par p
    h = ((mp - mq) * qPrime) % p

    # Calcul de la variable m comme le reste de la division de (mq plus h multiplié par q) par n
    m = (mq + h * q) % n

    return m


def home_pgcd(a, b):  # recherche du pgcd
    if (b == 0):
        return a
    else:
        return home_pgcd(b, a % b)


def home_string_to_int(x):  # pour transformer un string en int
    z = 0
    for i in reversed(range(len(x))):
        z = int(ord(x[i])) * pow(2, (8 * i)) + z
    return (z)


def home_int_to_string(x):  # pour transformer un int en string
    txt = ''
    res1 = x
    while res1 > 0:
        res = res1 % (pow(2, 8))
        res1 = (res1 - res) // (pow(2, 8))
        txt = txt + chr(res)
    return txt


# def mot10char():  # entrer le secret
#     secret = input("donner un secret de 10 caractères au maximum : ")
#     while (len(secret) > 21):
#         secret = input("c'est beaucoup trop long, 10 caractères S.V.P : ")
#     return (secret)

def mot50char():  # entrer le secret
    secret = input("donner un secret de 50 caractères au maximum : ")
    while (len(secret) > 51):
        secret = input("c'est beaucoup trop long, 50 caractères S.V.P : ")
    return (secret)


def créationBlocsMessage(message):
    # Initialisation de la liste de blocs et limite du k
    m = []

    if len(message) % 2 == 0:  # le message a une longueur paire
        limit = len(message) // 2
    else:  # le message a une longueur impaire
        limit = (len(message) - 1) // 2

    j = random.randint(2, limit)

    print( "\ntaille de j:",j,"\n")
    # Boucle pour couper le message
    while len(message) > j:
        mi = message[:j]
        m.append(mi)
        message = message[j:]

    # Ajout de la dernière sous-chaîne
    m.append(message)
    print("Messages : ", m)

    return m


def blocDecimal(messages):
    messageDecimal = []
    for m in messages:
        messageDecimal.append(home_string_to_int(m))
    print("Version en nombre décimal des messages ", messageDecimal)
    return messageDecimal


def creationBloc(messages):
    blocks = []
    limitK = 60
    k = random.randint(5, limitK)
    print('taille de k :', k)
    for m in messages:
        sizeX = k-len(str(m)) - 4 # 𝑘 − 𝑗 − 3 octets sous forme de caracteres
        print('taille de x :', sizeX)

        nb_max = 10 ** sizeX - 1  # la valeur maximale de l'intervalle

        while True:
            x = secrets.randbelow(nb_max) + 1  # génère un nombre aléatoire dans l'intervalle (1, nb_max)
            if len(str(x)) == sizeX:  # vérifie que le nombre a x chiffres
                break

        print('x :', x)
        # Construire le bloc de la forme : 00‖02‖x‖00‖𝑚𝑖‖
        block = '00' + '02' + str(x) + '00' + str(m)

        blocks.append(block)

    print('blocks :', blocks)
    return blocks


def blocsRSA(blocks, ea, na):
    chiffblocks = []
    for m in blocks:
        chiff = home_mod_expnoent(int(m), ea, na)
        chiffblocks.append(chiff)

    print("voici les blocks message chiffré avec la publique d'Alice : \n", chiffblocks)
    return chiffblocks

def blocsRSAinv(blockschiffree, da, na):
    dechiffblocks = []
    for m in blockschiffree:
        dechiff = home_mod_expnoent(m, da, na)
        dechiffblocks.append(dechiff)

    print("Alice déchiffre le bloc message chiffré rendu en decimal: \n", dechiffblocks)
    return dechiffblocks

def dechiffrementRSAblocs(dechiffblocks):
    dechiffblocksMessage = []
    dechiffblocksMessageString = []
    for m in dechiffblocks:
        bloc_str = str(m)
        for i in range(len(bloc_str)):
            if bloc_str[i:i + 2] == '00':
                bloc_str = bloc_str[i + 2:]
                break
        dechiffblocksMessage.append(int(bloc_str))
    print("Alice obtient les message decimaux: \n", dechiffblocksMessage)

    for md in dechiffblocksMessage:
        blocstring = home_int_to_string(md)
        dechiffblocksMessageString.append(blocstring)
    print("Alice obtient les messages : \n", dechiffblocksMessageString)

    messageEnvoye = "".join(dechiffblocksMessageString)
    print("Pour finir, alice regroupe les differents blocs et recupere le message envoyé: \n", messageEnvoye)

    return messageEnvoye



# voici les éléments de la clé d'Alice
# x1a = 2010942103422233250095259520183  # p
# x2a = 3503815992030544427564583819137  # q
x1a = 608374008321988961645676216446814912308108652191114995556897  # p nouvelle clef de 60 caracteres pour sha256
x2a = 310862287259718118908416875730252948527603190886142270567957  # q nouvelle clef de 60 caracteres pour sha256
na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // home_pgcd(x1a - 1, x2a - 1)
ea = 17  # exposant public
da = home_ext_euclide(phia, ea)  # exposant privé
# voici les éléments de la clé de bob
# x1b = 9434659759111223227678316435911  # p
# x2b = 8842546075387759637728590482297  # q
x1b = 762807463949654769548656894998136037163904829497830908642209  # p nouvelle clef de 60 caracteres pour sha256
x2b = 357925266421579046844087625375712068094818394193046496285147  # q nouvelle clef de 60 caracteres pour sha256
nb = x1b * x2b  # n
phib = ((x1b - 1) * (x2b - 1)) // home_pgcd(x1b - 1, x2b - 1)
eb = 23  # exposants public
db = home_ext_euclide(phib, eb)  # exposant privé

print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =", nb)
print("exposant :", eb)
print("voici votre précieux secret")
print("d =", db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =", na)
print("exposent :", ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x = input("appuyer sur entrer")
secret = mot50char()



print("*******************************************************************")
print("Méthode inspirée de PKCS#1v1.5 :\n" )
messagebloc = créationBlocsMessage(secret)
messageDecimalBloc = blocDecimal(messagebloc)
messageBlocksComplets = creationBloc(messageDecimalBloc)
messageBlocksCompletsChiffrees = blocsRSA(messageBlocksComplets, ea, na)
dechiffrageBlocks = blocsRSAinv(messageBlocksCompletsChiffrees, da, na)
dechiffrementRSAblocs(dechiffrageBlocks)
print("*******************************************************************")



print("*******************************************************************")
print("voici la version en nombre décimal de ", secret, " : ")
num_sec = home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la publique d'Alice : ")
chif = home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
# print("On utilise la fonction de hashage MD5 pour obtenir le hash du message", secret)
# Bhachis0 = hashlib.md5(secret.encode(encoding='UTF-8', errors='strict')).digest()  # MD5 du message
print("On utilise la fonction de hashage SHA-256 pour obtenir le hash du message avec plus de sécurité", secret)
Bhachis0 = hashlib.sha256(secret.encode(encoding='UTF-8', errors='strict')).digest()  # SHA-256 du message
print("voici le hash en nombre décimal ")
Bhachis1 = binascii.b2a_uu(Bhachis0)
Bhachis2 = Bhachis1.decode()  # en string
Bhachis3 = home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe = home_mod_expnoent(Bhachis3, db, nb)
print(signe)

print("voici la signature avec la clé privée de Bob du hachis avec le CRT")
signe2 = CRT(x1b, x2b, db, Bhachis3)
print(signe2)

print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n", chif, "\n \t 2-et le hash signé \n", signe)
print("*******************************************************************")
x = input("appuyer sur entrer")
print("*******************************************************************")
print("Alice déchiffre le message chiffré \n", chif, "\nce qui donne ")
dechif = home_int_to_string(home_mod_expnoent(chif, da, na))
print(dechif)

print("Déchiffrement par le CRT : ")
dechiffreCRT=CRT(x1a,x2a,da, chif)
print("Alice déchiffre  le message chiffré avec la clé de Bob \nCe qui donne : ")
print(home_int_to_string(dechiffreCRT))

print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n", signe, "\n ce qui donne  en décimal")
designe = home_mod_expnoent(signe, eb, nb)
print(designe)

print("Alice déchiffre la signature CRT de Bob \n", signe2, "\n ce qui donne  en décimal")
designe2 = home_mod_expnoent(signe2, eb, nb)
print(designe2)

print("Alice vérifie si elle obtient la même chose avec le hash de ", dechif)
Ahachis0 = hashlib.sha256(dechif.encode(encoding='UTF-8', errors='strict')).digest()
Ahachis1 = binascii.b2a_uu(Ahachis0)
Ahachis2 = Ahachis1.decode()
Ahachis3 = home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =", Ahachis3 - designe)
if (Ahachis3 - designe == 0):
    print("Alice : Bob m'a envoyé : ", dechif)
else:
    print("oups")

print("La différence pour le CRT =", Ahachis3 - designe2)
if (Ahachis3 - designe2 == 0):
    print("Alice : Bob m'a envoyé : ", dechif)
else:
    print("oups")
