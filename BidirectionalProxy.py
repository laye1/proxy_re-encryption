# Implementation d'Algorithme de rechiffrement proxy bidirectionnel basé sur le schéma Elgamal
# @LayeNdiaye 
 
import random
import math

# Modular exponentiation 
def power(a, b, c):
    x = 1
    y = a
 
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
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


## Génération de clés
# Cette fonction prend en entrée un grand nombre q dans Z
# génère les clés privées de Alice -key_priv_a, de Bob -key_priv_b,
# du proxy -key_priv_p
# génère les clés public de Alice, de Bob, du Proxy
# publier les paramétres public q, g

def genkeys_g(q):

   g = random.randint(2, q-1)
   while math.gcd(q, g) != 1:
    g = random.randint(2, q-1)

   key_priv_a = random.randint(2, q-1)
   while math.gcd(q, key_priv_a) != 1:
         
         key_priv_a = random.randint(2, q-1)

   key_priv_b = random.randint(2, q-1)
   while math.gcd(q, key_priv_b) != 1:
         
         key_priv_b = random.randint(2, q-1)
         
   key_priv_p = (key_priv_a - key_priv_b)
   
   key_pub_a = power(g, key_priv_a, q)

   key_pub_b = power(g, key_priv_b, q)

   key_pub_p = power(g, key_priv_p, q)

   return q,g,key_pub_b,key_pub_a,key_pub_p,key_priv_a,key_priv_b,key_priv_p   

	
# Cette fonction permet de chiffrer un message venant de Alice ou de Bob 
# La  fonction prend en entré le message de Alice ou Bob, les parametre public g,q, 
# la clé public de Alice ou Bob 
# sortie deux chiffrés (encrypt_msg1, encrypt_msg2)

def encrypt_msg(msg,g,q,key_pub):

    r = random.randint(2,q-1)

    encrypt_msg1 = power(g, r, q)
    encrypt_msg2 = []
    
     
    for i in range(0, len(msg)):
        encrypt_msg2.append(msg[i])
 
    for i in range(0, len(encrypt_msg2)):
           encrypt_msg2[i] = (power(key_pub,r,q) * ord(encrypt_msg2[i])) % q
 
    return encrypt_msg1, encrypt_msg2



## message chiffré par le Proxy
# Cette fonction prend en entré les messages chiffrés par Alice ou Bob,
# le paramètre public q
# puis rechiffre le chiffé de Alice ou Bob avec sa clé public,
# et renvoi un autre chiffré en sortie
def encrypt_Proxy(encrypt_msg2,encrypt_msg1, q, key_pub_proxy):
 
    encrypt_msg = []
     
    for i in range(0, len(encrypt_msg2)):
        encrypt_msg.append(encrypt_msg2[i])
 
    for i in range(0, len(encrypt_msg)):
           
       encrypt_msg[i] = int(power(encrypt_msg1,key_pub_proxy,q) 
                                        * int(encrypt_msg[i])) % q
    return encrypt_msg
 
## message déchiffré par le proxy
# Cette fonction prend en entré le message chiffré par le proxy,
# le chiffré encrypt_msg1 de Alice ou Bob
# la clé privé du proxy,le paramètre public q
# puis déchiffre le chiffré avec sa clé privée et renvoie le message déchiffré en sortie
def decryptProxy(encrypt_msg,encrypt_msg1,key_priv_Proxy,q ):

    decrypt_msg = []
   
    for i in range(0, len(encrypt_msg)):
         decrypt_msg.append((encrypt_msg[i] * 
                             modinv(power(encrypt_msg1,key_priv_Proxy,q),q)) % q)
    return  decrypt_msg 
   
## message déchiffré par Alice ou Bob
# Cette fonction prend en entré le message déchiffré par le proxy, 
# le chiffré encrypt_msg1 de Alice ou Bob
# la clé privée du proxy, le paramètre public q et renvoie le message déchiffer en sortie
def decrypt_msg(msg,encrypt_msg1,key_priv_,q):
  
    new_msg = []

    for i in range(0, len(msg)):
           
      new_msg.append(chr((int(msg[i] * 
                             modinv(power(encrypt_msg1,key_priv_,q),q)) % q )))
     
                         
    return new_msg
                        
def main():
 
    print("### Rechiffrement Proxy Bidirectionnel ###")
    
    msg_a = input("Message envoyé à Bob par Alice:")
    msg_b = input("Message envoyé à Alice par Bob:")

    q = random.randint(100000000000, 1000000000000)
   
    q,g,key_pub_b,key_pub_a,key_pub_p,key_priv_a,key_priv_b,key_priv_p = genkeys_g(q)
    
    print("\n Le paramètre public q:",q)
    print("\n Le paramètre public g:",g)
    print("\n La clé  privee de Bob:",key_priv_b)
    print("\n La clé privée de Alice:",key_priv_a)
    print("\n La clé privée du Proxy:",key_priv_p)
    print("\n La clé  public de Bob:",key_pub_b)
    print("\n La clé public de Alice:",key_pub_a)
    print("\n La clé public du Proxy:",key_pub_p)
 
    print("\n #Alice chiffre les message et envoie à Bob qui proccède au déchiffrement #")
    
    encrypt_msga1, encrypt_msga2 = encrypt_msg(msg_a,g,q,key_pub_b)

    print("\n Message chiffré par Alice :", encrypt_msga2 )

    en_msg_proxy1 = encrypt_Proxy(encrypt_msga2,encrypt_msga1, q, key_priv_p)

    print("\n Message chiffré par le Proxy :", en_msg_proxy1 )    
    
    decrypt_msg_proxy1 = decryptProxy(en_msg_proxy1,encrypt_msga1,key_priv_p,q )
    
    print("\n Message déchiffré par le Proxy :", decrypt_msg_proxy1 )
    
    decrypt_msg_bob = decrypt_msg(decrypt_msg_proxy1,encrypt_msga1,key_priv_b,q)

    print("\n Message déchiffré par Bob :", decrypt_msg_bob)

    origin_msg = ''.join(decrypt_msg_bob)

    print("\n Et on obtient le message d'origine :", origin_msg );

    print("\n # Bob chiffre les message et envoie à Alice qui proccède au déchiffrement #")

    encrypt_msgb1, encrypt_msgb2 = encrypt_msg(msg_b,g,q,key_pub_a)

    print("\n Message chiffré par Bob :", encrypt_msgb2)

    en_msg_proxy2 = encrypt_Proxy(encrypt_msgb2,encrypt_msgb1, q, key_priv_p)

    print("\n Message chiffré par le Proxy :", en_msg_proxy2 )

    decrypt_msg_proxy2 = decryptProxy(en_msg_proxy2,encrypt_msgb1,key_priv_p,q )

    print("\n Message déchiffré par le Proxy :", decrypt_msg_proxy2 )

    decrypt_msg_alice = decrypt_msg(decrypt_msg_proxy2,encrypt_msgb1,key_priv_a,q)

    print("\n Message déchiffré par Bob :", decrypt_msg_alice);

    origin_msg1 = ''.join(decrypt_msg_alice)

    print("\n Et on obtient le message d'origine :", origin_msg1 );


if __name__ == '__main__':
    main()