
# the key is not in the firmware distrubuted to the participante they need to calcualte it from the provided power traces
from scipy import stats
import numpy as np




def correlation_power_analysis(sbox):
    traces = np.load('traces.npy')
    textin = np.load('plaintext.npy') 
    key_num = 256
    trace_num = np.shape(traces)[0]
    sample_num = np.shape(traces)[1]
    key_size = 16
    correct_key = []


    for i in range(key_size): 
        print(f"Analyzing the {i}th key byte ...")
        # calculate all possible sbox values for all possible keys for a specific byte in all input
        data_in = [x[i] for x in textin]
        intermedia_values = np.zeros([trace_num,key_num],dtype=np.uint8)
        for y in range(len(data_in)) :
            for x in range(key_num):
                intermedia_values[y,x] = sbox[data_in[y] ^ x]

        # calculate the power model .i.e Hamming Weight value for all intermediate_values
        Hammin_Weight = np.zeros([trace_num,key_num],dtype=np.uint8)
        for y in range(len(data_in)) :
            for x in range(key_num):
                Hammin_Weight[y,x] = bin(intermedia_values[y,x]).count('1')

       # calculate the power correlation factor using Pearson method
        correlation = np.zeros([key_num,sample_num],dtype=np.float32)
        for x in range(key_num):
            for y in range(sample_num):
                correlation[x,y] = abs(stats.pearsonr(Hammin_Weight[:,x],traces[:,y])[0])

        best_guess = np.flip(np.argsort(np.amax(correlation,1)))[0]
        print(f"the best guess for the {i}th key byte is {hex(best_guess)}")
        correct_key.append(best_guess)

    return correct_key


# we can also deduce the decryption algorithem after studing the encryption algorithem
def dec(data,key):    
    # generate the inverse of the sbox
    enc_flag = list(data)

    inv_sbox = np.zeros(256,dtype=np.uint8)
    for i in range(len(sbox)) :
        inv_sbox[sbox[i]] = i


    for i in range(8):
        enc_flag_0 = enc_flag[0]
        enc_flag[0] = enc_flag[1]
        enc_flag[1] = enc_flag[2]
        enc_flag[2] = enc_flag[3]
        enc_flag[3] = enc_flag[4]
        enc_flag[4] = enc_flag[5]
        enc_flag[5] = enc_flag[6]
        enc_flag[6] = enc_flag[7]
        enc_flag[7] = enc_flag_0


        enc_flag[8]  = key[8]  ^ inv_sbox[enc_flag[0]  ^ enc_flag[8]];
        enc_flag[9]  = key[9]  ^ inv_sbox[enc_flag[1]  ^ enc_flag[9]];
        enc_flag[10] = key[10] ^ inv_sbox[enc_flag[2]  ^ enc_flag[10]];
        enc_flag[11] = key[11] ^ inv_sbox[enc_flag[3]  ^ enc_flag[11]];
        enc_flag[12] = key[12] ^ inv_sbox[enc_flag[4]  ^ enc_flag[12]];
        enc_flag[13] = key[13] ^ inv_sbox[enc_flag[5]  ^ enc_flag[13]];
        enc_flag[14] = key[14] ^ inv_sbox[enc_flag[6]  ^ enc_flag[14]];
        enc_flag[15] = key[15] ^ inv_sbox[enc_flag[7]  ^ enc_flag[15]];

        enc_flag[0] = key[0] ^ inv_sbox[enc_flag[0]]
        enc_flag[1] = key[1] ^ inv_sbox[enc_flag[1]]
        enc_flag[2] = key[2] ^ inv_sbox[enc_flag[2]]
        enc_flag[3] = key[3] ^ inv_sbox[enc_flag[3]]
        enc_flag[4] = key[4] ^ inv_sbox[enc_flag[4]]
        enc_flag[5] = key[5] ^ inv_sbox[enc_flag[5]]
        enc_flag[6] = key[6] ^ inv_sbox[enc_flag[6]]
        enc_flag[7] = key[7] ^ inv_sbox[enc_flag[7]]



    return enc_flag

# from reverse engineering the firmware we can find the sbox + encryption algorithem
sbox = np.array([
    0x8C , 0x5A , 0x00 , 0xBF ,
0xC8 , 0xAF , 0x55 , 0x35 ,
0xC6 , 0x50 , 0xD9 , 0x7F ,
0x01 , 0xE1 , 0x84 , 0xB5 ,
0x41 , 0x43 , 0xDA , 0xF2 ,
0xC7 , 0xE9 , 0xB3 , 0x88 ,
0x12 , 0xF8 , 0xA6 , 0x5D ,
0xD5 , 0xE5 , 0x28 , 0x36 ,
0x74 , 0xB6 , 0x34 , 0x19 ,
0xF3 , 0x2F , 0x59 , 0xA3 ,
0xF9 , 0xEA , 0x2B , 0x9B ,
0xC9 , 0xE3 , 0x9D , 0x07 ,
0x78 , 0xBC , 0x99 , 0x56 ,
0xD3 , 0x17 , 0xB0 , 0x30 ,
0x5E , 0x16 , 0x08 , 0x96 ,
0x0C , 0x3B , 0xF1 , 0xD2 ,
0x1D , 0xD4 , 0x06 , 0xF7 ,
0x25 , 0x89 , 0x8F , 0xCF ,
0xBD , 0x4F , 0xD0 , 0x0A ,
0xB2 , 0xC4 , 0xCB , 0xE4 ,
0x6F , 0x73 , 0xFD , 0x0E ,
0x22 , 0x66 , 0x21 , 0x1B ,
0xD8 , 0x5B , 0x46 , 0x6C ,
0x48 , 0x2D , 0x6B , 0x3F ,
0x5F , 0x04 , 0x54 , 0x3D ,
0x9A , 0xA5 , 0x70 , 0x2E ,
0xF0 , 0xDD , 0xDE , 0x09 ,
0xD1 , 0xB1 , 0x3E , 0x7A ,
0x69 , 0x0F , 0x51 , 0x2C ,
0xA8 , 0x67 , 0xA4 , 0x6D ,
0xAC , 0x76 , 0x87 , 0xB4 ,
0x0D , 0xCE , 0xB9 , 0x18 ,
0x32 , 0x42 , 0xFF , 0xA1 ,
0xC5 , 0xBA , 0xEC , 0x47 ,
0x23 , 0xEF , 0x8A , 0x11 ,
0xA7 , 0x39 , 0xC2 , 0xBE ,
0x75 , 0xE8 , 0x68 , 0x81 ,
0x38 , 0xB7 , 0xD7 , 0x63 ,
0xFB , 0x7D , 0x3A , 0x6E ,
0x45 , 0x26 , 0xCC , 0x9C ,
0x05 , 0x80 , 0x7C , 0x71 ,
0x8E , 0xFC , 0xDF , 0x1A ,
0x1C , 0x93 , 0x14 , 0x95 ,
0x64 , 0x1F , 0x03 , 0x4A ,
0xAD , 0x3C , 0x20 , 0x2A ,
0x37 , 0xE6 , 0x85 , 0x27 ,
0x52 , 0x8B , 0x82 , 0xE7 ,
0xA9 , 0x77 , 0x13 , 0xF6 ,
0xAA , 0xC3 , 0xFA , 0x91 ,
0x6A , 0xCD , 0x29 , 0x62 ,
0x24 , 0xA2 , 0xE2 , 0x31 ,
0x83 , 0x15 , 0xBB , 0xCA ,
0xAB , 0x40 , 0xE0 , 0x02 ,
0x86 , 0x4C , 0x60 , 0x92 ,
0x72 , 0xF4 , 0x5C , 0x53 ,
0xDC , 0x0B , 0xEB , 0xA0 ,
0x79 , 0xC1 , 0xFE , 0x8D ,
0x9F , 0x61 , 0x98 , 0xAE ,
0x90 , 0xDB , 0x1E , 0x4E ,
0xB8 , 0x9E , 0x97 , 0x4D ,
0xEE , 0x10 , 0x65 , 0xD6 ,
0x94 , 0x7E , 0x58 , 0x4B ,
0x44 , 0x49 , 0x33 , 0x7B ,
0xF5 , 0xED , 0x57 , 0xC0 

])
key = correlation_power_analysis(sbox)

f = open('encrypted_flag','rb')
flag = f.read()
flag = dec(flag,key)
print(f"The Decrypted Flag is : {''.join([chr(i) for i in flag])}")
