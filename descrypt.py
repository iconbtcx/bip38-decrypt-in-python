print ("loading...")
from bip38 import *
import multiprocessing


#  donate   3FenijcfTqxWUEbVxQ3VEkkAVe7iNLHJK2

# bip38 enscrypted

bip1 = "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7"
s= ' '
a1="Satoshi"
def main():
    while True:
        password = "pass.txt"
        file = open(password, "r")
        choices=[]
        with file as f:
            words = f.read().split()
            for word in words:
                x = [1]
                xa = random.choice(x)
                sent = [random.choice(words)
                for word in range(int(xa))]
                if sent not in choices:
                    choices.append(sent)
                    paswd = ' '.join(sent)
                    
                    h1= bip38_decrypt(bip1, paswd)
                    
if __name__ == '__main__':
    thread = int(input("Enter number of thread's here: "))
    for cpu in range(thread):
    	multiprocessing.Process(target = main).start()