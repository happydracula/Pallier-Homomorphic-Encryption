import numpy as np 
import utils
import time
import gmpy2

from gmpy2 import mpz,mpq,mpfr,mpc
gmpy2.set_context(gmpy2.context())
class PublicKey:
    def __init__(self,n,g):
        self.n=mpz(n)
        self.g=mpz(g)
    def encrypt(self,m):
        m=mpz(m)
        if(m>=self.n):
            raise Exception("The plaintext is larger than the modulus n")
            return 
        else:
            r=utils.getRandomCoPrime(self.n)
           
            c=mpz((pow(self.g,m,self.n*self.n)*pow(r,self.n,self.n*self.n))%(self.n**2))
            ciphertext =CipherText(c,self.n,self.g)
            return ciphertext
class CipherText:
    
    def __init__(self,c,n,g):
        self.c=c
        self.n=n
        self.g=g
        
    def __add__ (self,other):
        if(not isinstance(other,CipherText)):
            raise Exception("You can only add one ciphertext to another as of now!!")
        elif(self.n!=other.n or self.g!=other.g):
            raise Exception("You can only add  ciphertexts encrypted by same key!!")
        else:
            return CipherText(gmpy2.mul(self.c,other.c)%(self.n**2),self.n,self.g)
    def __sub__(self,other):
        if(not isinstance(other,CipherText)):
            raise Exception("You can only add one ciphertext to another as of now!!")
        elif(self.n!=other.n or self.g!=other.g):
            raise Exception("You can only add  ciphertexts encrypted by same key!!")
        else:
            return CipherText(gmpy2.mul(self.c,utils.modInverse(other.c,self.n**2))%(self.n**2),self.n,self.g)
class PrivateKey:
    def __init__(self,n,l,mu):
        self.n=n
        self.l=l
        self.mu=mu
    def decrypt(self,c):
        c=mpz(c)
        return (utils.Lfunc(pow(c,self.l,self.n**2),self.n)*self.mu)%self.n

class Pallier:
    
    def __init__(self,n_bits=100):
        self.n_bits=mpz(n_bits)
    def key_gen(self):
        p=mpz(utils.large_prime(self.n_bits))
        q=mpz(utils.large_prime(self.n_bits))
        n=p*q
        g=n+1
        l=(p-1)*(q-1)
        mu=utils.modInverse(l,n)
        public_key=PublicKey(n,g)
        private_key=PrivateKey(n,l,mu)
        return private_key,public_key
   
        

if __name__ =="__main__":
    pallier=Pallier(512)
    private_key,public_key=pallier.key_gen()
    a=50
    b=100
    c1=public_key.encrypt(a)
    c2=public_key.encrypt(b)
    c3=c2-c1
   
    print(private_key.decrypt(c1.c))
    print(private_key.decrypt(c2.c))
    print(private_key.decrypt(c3.c))
