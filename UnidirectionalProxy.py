
# Implementation d'Algorithme de rechiffrement proxy Unidirectionnel
# basé sur le schéma Elgamal
# @LayeNdiaye 

import random
from math import pow
import math

# Modular exponentiations
def power(a, b, c):
    x = 1
    y = a
 
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c;
        y = (y * y) % c
        b = int(b / 2)
 
    return x % c

# inverse modulo
def modinv(a, m): 
    b = m
    s, s1 = 1, 0
    while b:
        a, (q, b) = b, divmod(a, b)
        s, s1 = s1, s - q * s1
    if a != 1:
        raise ValueError('inverse does not exist')
    else: 
           return s if s >= 0 else s + m
 
# Génération de clés
# Cette fonction prend en entrée un grand nombre q dans Z
# génère les clés privées de alice -key_priv_A,
# -key_priv_Bob de Bob,-key_priv_Proxy du proxy 
# publier les paramétres public q, g, gkey_priv_A

def genkeys_g(q):

   g = random.randint(2, q-1)
   while math.gcd(q, g) != 1:
    g = random.randint(2, q-1)

   key_priv_A = random.randint(2, q-1)
   while math.gcd(q, key_priv_A) != 1:
         
         key_priv_A = random.randint(2, q-1)

   key_priv_Proxy = random.randint(1, key_priv_A)
   key_priv_Bob = (key_priv_A - key_priv_Proxy)%q

   key_pub_A = power(g, key_priv_A, q)
 

   return q, g, key_pub_A, key_priv_Proxy, key_priv_Bob

    
## message chiffré par ALice
# Cette fonction prend en entré le message de Alice, les parametre public g,q, 
# la clé public de Alice key_pub_A
# sortie deux chiffrés (encrypt_msg1, encrypt_msg2)

def encrypt_Alice(msg,g,q,key_pub_A):

    r = random.randint(2,q-1)

    encrypt_msg1 = power(g, r, q)
    encrypt_msg2 = []
    
     
    for i in range(0, len(msg)):
        encrypt_msg2.append(msg[i])
 
    for i in range(0, len(encrypt_msg2)):
           encrypt_msg2[i] = (power(key_pub_A,r,q) * ord(encrypt_msg2[i])) % q
 
    return encrypt_msg1, encrypt_msg2

## message déchiffré par le proxy
# Cette fonction prend en entré les messages chiffrés par Alice,
#  la clé privée du proxy,le paramètre public q
# puis déchiffre le chiffé de Alice avec sa clé privée,
# et renvoi le message déchiffré en sortie

def decryptProxy(encrypt_msg2,encrypt_msg1,key_priv_Proxy,q ):

    decrypt_msg = []
   
    for i in range(0, len(encrypt_msg2)):
                      
      decrypt_msg.append(((encrypt_msg2[i] * 
                           modinv(power(encrypt_msg1,key_priv_Proxy,q),q))) % q)
            
    return  decrypt_msg  

## message déchiffré par Bob
# Cette fonction prend en entré le message déchiffré par le proxy ,
# la clé privée du proxy, les paramètre public gkey_priv_A, q
def decryptBob(decrypt_msg_bob,encrypt_msg1,key_priv_Bob,q):
  
    decrypt_msg = []

    for i in range(0, len(decrypt_msg_bob)):
           
      decrypt_msg .append(chr((int(decrypt_msg_bob[i] * 
                            modinv(power(encrypt_msg1,key_priv_Bob,q),q) )% q)))
                           
    return decrypt_msg
                        
def main():
    print("#####******** Rechiffrement Proxy *********#####")
    msg = input("\n Message envoyé par Alice:")
    q = random.randint(1000000000, 100000000000)  
    q, g, key_pub_A, key_priv_Proxy, key_priv_Bob = genkeys_g(q)

    print("\n Le paramètre public q:",q)
    print("\n Le paramètre public g:",g)
    print("\n La clé  public de Alice:",key_pub_A)
    print("\n La clé privée du proxy:",key_priv_Proxy)
    print("\n La clé privée de Bob:",key_priv_Bob)
 
    encrypt_msg1, encrypt_msg2 = encrypt_Alice(msg,g,q,key_pub_A)
    print("\n Message chiffré par Alice:",encrypt_msg2)
     
    decrypt_msg_proxy = decryptProxy(encrypt_msg2,encrypt_msg1,key_priv_Proxy,q )
    
    print("\n Message déchiffré par le Proxy :", decrypt_msg_proxy);
    
    decrypt_msg_bob = decryptBob(decrypt_msg_proxy,encrypt_msg1,key_priv_Bob,q)
  
    print("\n Message déchiffré par le Bob:", decrypt_msg_bob)  

    msg_origin = ''.join(decrypt_msg_bob)

    print("\n On obtient  le massage d'origine :", msg_origin );
    
if __name__ == '__main__':
    main()