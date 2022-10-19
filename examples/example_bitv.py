import sys
sys.path.append('/home/cloudcvcsec')
from z3 import *

def split_and_concat_ipaddr(ip_addr):
    abcd=ip_addr.split('.')
    addr_bit_vec=[]
    for i in range(0,4):
        addr_bit_vec.append(z3.BitVecVal(abcd[i],8))
    ip_bits=z3.Concat(addr_bit_vec[0],addr_bit_vec[1],addr_bit_vec[2],addr_bit_vec[3])
    return ip_bits

def mask_and_match(ip_bits, mask_bits, ip_bits_new):
    masked_bits = ip_bits & mask_bits
    masked_ip_bits_new = ip_bits_new & mask_bits
    #print('Masked_bits size: '+ str(masked_bits.size()))
    print('Decimal of masked_bits: '+ str(z3.simplify(masked_bits)))
    print('Decimal of masked_ip_bits_new: ' + str(z3.simplify(masked_ip_bits_new)))
    print('\n')
    #print('Hexadecimal of masked_bits: ' + str(masked_bits.sexpr()))
    #print('Decimal of the prefixlen of masked_bits:'+ str(z3.simplify( z3.Extract(31,prefix_len,masked_bits))) )
    # return z3.simplify(z3.Extract(31,prefix_len,masked_bits) == z3.Extract(31,prefix_len,masked_ip_bits2)) <-This not required
    return z3.simplify(masked_bits == masked_ip_bits_new)

# Policy 0 : Allow src ip address of the format 11.22.33.0/24
src_ip0='11.22.33.0/24'
ip0_split=src_ip0.split('/')
ip0_bit_vec=split_and_concat_ipaddr(ip0_split[0])
# most significant bits for ip0 is first 24 bits
mask0_bit_vec=split_and_concat_ipaddr('255.255.255.0')

# Policy 1: Allow src ip address of the format 11.22.0.0/16
src_ip1='11.22.0.0/16'
ip1_split=src_ip1.split('/')
ip1_bit_vec=split_and_concat_ipaddr(ip1_split[0])
# most significant bits for ip1 is first 16 bits
mask1_bit_vec=split_and_concat_ipaddr('255.255.0.0')

#### Examples

#ip_bits_vec=split_and_concat_ipaddr('11.22.33.1') # true
#ip_bits_vec=split_and_concat_ipaddr('11.22.32.1') # false
# create bitvec variable for an ip address of the format a.b.c.d

ip_bits_vec= z3.Concat(z3.BitVec('a',8),z3.BitVec('b',8),z3.BitVec('c',8),z3.BitVec('d',8))

#Policy0 match
C0=mask_and_match(ip0_bit_vec, mask0_bit_vec, ip_bits_vec)
#print('C0: ip_addr allowed? ' + str(mask_and_match(ip0_bit_vec, mask0_bit_vec, ip_bits_vec, 24)))

#Policy1 match
C1=mask_and_match(ip1_bit_vec, mask1_bit_vec, ip_bits_vec)
#print('C1:ip_addr allowed? ' + str(mask_and_match(ip1_bit_vec, mask1_bit_vec, ip_bits_vec, 16)))

#Implications
print("C0 => C1:")
z3.prove(Implies(C0,C1))
print("C1 => C0: ")
z3.prove(Implies(C1,C0))

