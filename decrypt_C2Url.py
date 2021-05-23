import numpy as np
 
#----------------------------------------------------------------------
def calc_value(c, val_0x2C):
    """"""
    tmp = val_0x2C - 0x2B
    if tmp:
        tmp2 = tmp - 2
        if tmp2:
            if (tmp2 == 1):
                c = c + 0x85
            else:
                c = c & 0xFF
        else:
            c = c + 0x4B
    else:
        c = c - 0x30
     
    if (c < 0 or c > 0xFF):
        c = 0x3F
     
    return c   
 
#----------------------------------------------------------------------
def int_to_bytes(value, length):
    """"""
    result = []
 
    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)
 
     
    return result
 
     
#----------------------------------------------------------------------
def decrypt_c2url(encUrl, xor_tbl):
    """"""
    c2_url = ""
    dec_c2 = []
    j = 0
    len_c2 = len(encUrl)
    if len_c2 >= 4:
        i = len_c2 / 4       
        if (len_c2/4 -1 >= 0):
            counter = len_c2/4
            while counter:
                for k in range(len(xor_tbl)):                    
                    dec_c2.append(encUrl[j] ^ xor_tbl[j%len(xor_tbl)])
                    j+=1
                counter-=1
    j = 0
    if (len_c2 >= 4 *i +1):
        counter = len_c2 - 4 * i
        idx = 4 * i + 1
         
        while counter:
            dec_c2.append(encUrl[idx-1] ^ xor_tbl[j])
            j = (j + 1) % 4
            idx +=1
            counter-=1
     
    for i in dec_c2:
        c2_url += chr(i)
     
    return c2_url
             
#----------------------------------------------------------------------
def main():
    """"""
    C2_transform = [0] * len(encC2)
    tmp_tbl = []
    val_0x2C = 0x2C
    i = 1
    j = 1
     
    while j <= len(encC2):
        c = encC2[j -1]
        j+=1
        if ((c - 0x2B) >= 4):
            calced_val = calc_value(c, val_0x2C)
            C2_transform[i-1] = calced_val
            i+=1
        elif (c == val_0x2C):
            if (j > len(encC2)):
                break
            C2_transform[i-1] = encC2[j-1]
            i+=1
            j+=1
        else:
            val_0x2C = c
    C2_transform = np.trim_zeros(C2_transform)
    tmp_tbl = C2_transform[len(C2_transform)-2:len(C2_transform)]
    C2_transform = C2_transform[:len(C2_transform)-2]
    tmp_val = ((tmp_tbl[1] + (tmp_tbl[0] << 8)) & 0xF) + 0x10 * (tmp_tbl[1] & 0xF0) + (((tmp_tbl[1] + (tmp_tbl[0] << 8)) & 0xF00) << 8) + (((tmp_tbl[1] + (tmp_tbl[0] << 8)) & 0xF000) << 0xC)
    xor_tbl = int_to_bytes(tmp_val, 4)
         
    print decrypt_c2url(C2_transform, xor_tbl)