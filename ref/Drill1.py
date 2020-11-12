######
## Submitted by: Yehonatan Lusky
## ID: 315690677
######
import sys, random
try:
    from BitVector import *
except:
    print ("Bitvector module is part of the AES tables generation that was provided, can't continue without it")
    exit()
#Trying to import matplotlib
try:
    import matplotlib.pyplot as plt
except:
    print ("Can't print histograms because matplotlib is not installed")
    plt = None


AES_modulus = BitVector(bitstring='100011011')
# SBOX according to SPEC
subBytesTable = []                                                
invSubBytesTable = [] 

# randomly created SBOX
random_subBytesTable = []                                                
random_invSubBytesTable = [] 


def genTables():
    '''
    This function was take from the attached code by Avi Kak (February 15, 2015)
    '''
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))


def gen_random_tables():
    '''
    This function generates the random SBOX tables
    '''
    global random_subBytesTable, random_invSubBytesTable
    random_subBytesTable = [x for x in range(256)]
    random.shuffle(random_subBytesTable)
    random_invSubBytesTable = [0] * 256
    
    index = 0
    for val in random_subBytesTable:
        random_invSubBytesTable[val] = index
        index += 1
        
    
def get_text_stat(text):
    '''
    This function gets the current text statistics
    '''
    stat = {}
    text = text
    
    for i in text:
        if(len(str(hex(ord(i)))[2:]) == 2):
            value = str(hex(ord(i)))[2:]
        else:
            value = "0" + str(hex(ord(i)))[2:]
            
        if value in stat:
            stat[value] += 1
        else:
            stat[value] = 1
    
    return stat


def use_SBOX_over_text(text, sbox):
    ''' This function simply uses the sbox over each letter in the text '''
    new_text = ""
    for i in text:
        new_text += chr(sbox[ord(i)])
    
    return new_text
    

def plot_histogram(keys, values):
    '''
    This function prints a histogram according to the dictionarry and the values inside it
    '''
    plt.bar(keys, values, 1.0, color='g')
    plt.show()


def get_it_sorted(dict):
    ''' This function gets a dict and returns a tuple of two tuples sorted by keys '''
    keys = [] 
    values = []
    for i in sorted(dict):
        keys.append(i)
        values.append(dict[i])
    
    return (keys, values)
    


def ex_1_1(orig_text):

    # Print original text histogram
    print ("Plotting original text letter distribution")
    stats = get_text_stat(orig_text)
    keys, values = get_it_sorted(stats)
    plot_histogram(keys, values)
    
    # Print histogram according to the SPEC SBOX encryption
    print ("Plotting letter distribution of one round of SPEC SBOX over text")
    spec_enc_text = use_SBOX_over_text(orig_text, subBytesTable)
    stats = get_text_stat(spec_enc_text)
    keys, values = get_it_sorted(stats)
    plot_histogram(keys, values)
       
    # Print histogram according to the random SBOX encryption
    print ("Plotting letter distribution of one round of random SBOX over text")
    rand_enc_text = use_SBOX_over_text(orig_text, random_subBytesTable)
    stats = get_text_stat(rand_enc_text)
    keys, values = get_it_sorted(stats)
    plot_histogram(keys, values)
    
    return (spec_enc_text, rand_enc_text)
    
    

def ex_1_2(orig_text): 

    # Using spec SBOX over text 10 times
    spec_enc_text = orig_text
    for i in range(10):
        spec_enc_text = use_SBOX_over_text(spec_enc_text, subBytesTable)

    print ("This is the result of 10 rounds of spec SBOX:")
    print (spec_enc_text)
    print ("\n\tPlotting its histogram now\n")
    stats = get_text_stat(spec_enc_text)
    keys, values = get_it_sorted(stats)
    plot_histogram(keys, values)    
    
    #  Using rand SBOX over text 10 times
    rand_enc_text = orig_text
    for i in range(10):
        rand_enc_text = use_SBOX_over_text(rand_enc_text, random_subBytesTable)

    print ("This is the result of 10 rounds of random SBOX:")
    print (rand_enc_text)
    print ("\n\tPlotting its histogram now")
    stats = get_text_stat(rand_enc_text)
    keys, values = get_it_sorted(stats)
    plot_histogram(keys, values)
    
    return (spec_enc_text, rand_enc_text)
    
    
    

def ex_1_3(spec_enc_text, rand_enc_text, spec_enc_10_times, rand_enc_10_times):
    
     # Trying to decrypt the encrypted text by SPEC SBOX
    print ("Trying to decrypt the encrypted text by SPEC SBOX, This is the result:")   
    decrypted_text = use_SBOX_over_text(spec_enc_text, invSubBytesTable)
    print decrypted_text
    
    
    # Trying to decrypt the encrypted text by random SBOX
    print ("\n\nTrying to decrypt the encrypted text by random SBOX, This is the result:")
    decrypted_text = use_SBOX_over_text(rand_enc_text, random_invSubBytesTable)
    print decrypted_text   
      
    
    # Trying to decrypt the 10 times encrypted text by SPEC SBOX
    print ("\n\nTrying to decrypt the 10 times encrypted text by SPEC SBOX, This is the result:")
    
    decrypted_text = spec_enc_10_times
    for i in range(10):
        decrypted_text = use_SBOX_over_text(decrypted_text, invSubBytesTable)
    
    print decrypted_text
    
    
    # Trying to decrypt the 10 times encrypted text by random SBOX
    print ("\n\nTrying to decrypt the 10 times encrypted text by random SBOX, This is the result:")
   
    decrypted_text = rand_enc_10_times
    for i in range(10):
        decrypted_text = use_SBOX_over_text(decrypted_text, random_invSubBytesTable)
    
    print decrypted_text
    
    

def main():
    # Header
    print (80 * "=")
    print (("{:<30}{:^20}{:>30}").format(25*"=", "DRILL 1 Solution", 25*"="))
    print (80 * "=")

    # Initialization
    sys.stdout.write("\n### Initializing SBOX Tables.")
    sys.stdout.flush()
    
    genTables()
    sys.stdout.write(".")
    sys.stdout.flush()
    
    gen_random_tables()
    sys.stdout.write(".\n\n\n")
    sys.stdout.flush()
    
    # read file
    try:
        with open("text.txt", 'r') as in_file:
            orig_text = in_file.read()
    except:
        print ("Something went wrong, can't open text.txt file")
        exit()
    
    # Ex 1.1
    print (("{:<30}{:^20}{:>30}\n").format(30*"~", "Ex 1.1", 30*"~"))
    spec_enc_text, rand_enc_text = ex_1_1(orig_text)
    
    # Ex 1.2
    print (("\n{:<30}{:^20}{:>30}\n").format(30*"~", "Ex 1.2", 30*"~"))
    spec_enc_10_times, rand_enc_10_times = ex_1_2(orig_text)
    
    # Ex 1.3
    print (("\n{:<30}{:^20}{:>30}\n").format(30*"~", "Ex 1.3", 30*"~"))
    ex_1_3(spec_enc_text, rand_enc_text, spec_enc_10_times, rand_enc_10_times)

        
      

if __name__ == "__main__":
    main()