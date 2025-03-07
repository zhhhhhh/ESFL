import math

from charm.toolbox.integergroup import IntegerGroupQ, integer
from typing import List, Dict, Tuple
from src.helpers.additive_elgamal import AdditiveElGamal, ElGamalCipher
from src.helpers.helpers import reduce_vector_mod, get_int
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
import charm
import numpy as np
import hashlib
import random
#from src.helpers import dummy_discrete_log, get_int, get_modulus

# EDFE 名字

IntegerGroupElement = charm.core.math.integer.integer
ElGamalKey = Dict[str, IntegerGroupElement]
#生成群
debug = True
p1 = integer(
    148829018183496626261556856344710600327516732500226144177322012998064772051982752493460332138204351040296264880017943408846937646702376203733370973197019636813306480144595809796154634625021213611577190781215296823124523899584781302512549499802030946698512327294159881907114777803654670044046376468983244647367)
q1 = integer(
    74414509091748313130778428172355300163758366250113072088661006499032386025991376246730166069102175520148132440008971704423468823351188101866685486598509818406653240072297904898077317312510606805788595390607648411562261949792390651256274749901015473349256163647079940953557388901827335022023188234491622323683)
p = 2*p1+1

#print(p)

q = 2*q1+1
#print(q) 

N = p*q
N_squared = N ** 2  # 计算 N^2



elgamal_group = IntegerGroupQ()
elgamal = AdditiveElGamal(elgamal_group, p, q)
elgamal_params = {"group": elgamal_group, "p": int(p), "q": int(q), "N": int(p)*int(q)}

pk, sk = elgamal.keygen(1024)  #
g1 = pk['g']
g = pow(g1, (2*N), N_squared)

#输出群
def output_p():
    """
    输出群组和大素数p

    Returns:
        dict: 包含群组和大素数p的字典
    """
    return {"group": elgamal_group, "p": int(p)}
#创建哈希函数
# def H1(data: str, p: integer) -> integer:  # 参数扩充，
#     """
#     创建哈希函数
#
#     Args:
#         data (str): 需要哈希的数据
#         p (int): 大素数p
#
#     Returns:
#         int: 哈希后的结果
#     """
#     hash_object = hashlib.sha256(data.encode('utf-8'))
#     r = int(hash_object.hexdigest(), 16)
#     while r >= 10:
#         r //= 10
#       # 哈希函数：确保哈希函数返回的结果在合理范围内。当前实现中，哈希值被不断除以 10 直到小于 10，这可能不是预期的行为。建议改为取模操作：
#     return r
#     #return integer(int(hash_object.hexdigest(), 16))

def H1(data: str, p: integer) -> integer:
    """
    计算给定数据的哈希值，并返回基于质数p的哈希结果。

    参数:
    data: 需要计算哈希值的字符串数据。
    p: 一个整数，通常为质数，用于哈希计算中的模运算。

    返回:
    返回一个整数，为data的SHA-256哈希值与p进行模运算的结果。
    """
    # 使用SHA-256算法计算数据的哈希值
    hash_object = hashlib.sha256(data.encode('utf-8'))
    # 将哈希值从十六进制转换为整数
    r = int(hash_object.hexdigest(), 16)
    # 返回哈希结果与p进行模运算的结果
    return r % int(p)


#生成公钥密钥
def set_up(security_parameter: int, vector_length: int) -> Tuple[List[ElGamalKey], List[ElGamalKey]]:
    # N=p*q
    N = elgamal_params['N']
    # 初始化主公钥和主密钥列表
    master_public_key = [None] * vector_length
    master_secret_key = [None] * vector_length
    # 为每个向量元素生成ElGamal密钥对
    for i in range(vector_length):
        (master_public_key[i], master_secret_key[i]) = elgamal.keygen(secparam=security_parameter)  #
        
        ##公钥发生变化
        master_public_key[i] = pow(g, (master_secret_key[i]['x']), N_squared)
        
        master_public_key[i] = {'h': master_public_key[i]}
        #print(master_public_key[i])
    # master_public_key 的内容是： 类型：List[ElGamalKey]   # 内容：每个元素是一个字典，包含 ElGamal 公钥的信息，例如：{'h': <IntegerGroupElement>, 'g': <IntegerGroupElement>}
    return master_public_key, master_secret_key, int(N)  # 输出公私，和大素数乘积


#生成密钥
def KeyDerive(master_secret_key: List[ElGamalKey], master_public_key2:List[ElGamalKey], master_secret_key2: List[ElGamalKey], ctr: int, y: List[int], aux: str) -> integer:
    """
    导出一个派生密钥。

    该函数通过结合主密钥、次级密钥、计数器、向量y和辅助字符串来导出一个新的密钥。
    这个过程包括使用离散对数难题和哈希函数来确保密钥的安全性。

    参数:
    - master_secret_key: 主密钥，用于密钥导出的核心部分。
    - master_public_key2: 次级公钥列表，与次级密钥一起使用以增强安全性。
    - master_secret_key2: 次级密钥列表，与次级公钥对应。
    - ctr: 计数器，用于确保每次密钥导出的唯一性。
    - y: 一个整数列表，用于密钥导出的向量部分。
    - aux: 辅助字符串，用于增加密钥导出的熵。

    返回:
    - integer: 导出的密钥，作为一个整数返回。
    """
    #y = reduce_vector_mod(y, elgamal_params['p'])   # y的个数要跟encrtyptor的个数一致，encryptor个数为3，y的长度也为3
    ctr += 1      # 计数器增加1。
    skf = integer(0)# 初始化一个'skf'，初始值为整数0

    for i in range(len(y)):
        sk2i = master_secret_key2[i] # 获取次级公钥列表中的第i个公钥。
        pk2i = master_public_key2[i] # 将主公钥的第二个元素存储到变量pk2i中
        key = pow(pk2i['h'], master_secret_key['x'], N_squared) # 计算共享密钥，通过主密钥的私钥部分 master_secret_key['x'] 对次级公钥 pk2i['h'] 进行指数运算，生成一个共享密钥 key。这一步利用了离散对数难题来确保安全性。
        #print(key)
        r = H1(f"{key}{ctr}{aux}", elgamal_params['p']) # H1哈希函数 # pk2i的'g'分量的master_secret_key次方，pk2i的'x'分量，计数器ctr，辅助字符串aux，以及模数p。
        #print("tp's r is:",r)
        skf += r * y[i]  # 函数秘钥，内积
    #print("skf:",skf)
    #print(type(skf))
    
    return skf #reduce_vector_mod([skf], N_squared)[0]# 返回通过'reduce_vector_mod'函数将密钥因子模p约减以确保其在正确的密钥空间范围内的结果。
    

def Encrypt(master_public_key: List[ElGamalKey], master_secret_key2: List[ElGamalKey],
            master_public_key3:List[ElGamalKey],ctr: int,  X : List[int], aux: str, N: integer)-> integer:

    C = []  # 存密文
    ctr += 1
    N_squared = integer(N ** 2)  # 计算 N^2
    pk1 = master_public_key['h']  # 获取 pk1
    term2_test = 1
    r_sum = 0

    for i in range(len(X)):
        sk2i = master_secret_key2[i]  # 获取次级公钥列表中的第i个公钥。
        key = pow(pk1, sk2i['x'], N_squared) 
        r = H1(f"{key}{ctr}{aux}", elgamal_params['p'])  # 计算 r
        r = int(r)
        #print("clients's r is:",int(r))
        # pk1_r = pow(pk1, r, N_squared)  # 计算 pk1^r mod N^2
        # term1 = (1 + X[i] * elgamal_params['N']) % N_squared  # 计算 (1 + Xi * N) mod N^2
        # C_i = (term1 * pk1_r) % N_squared  # 计算 Ci
        # C_i = ((integer(1) + X[i] * elgamal_params['N'])*pow(pk1,r)) % N_squared
        ###
        term1 = (1 + X[i]*N)  % N_squared
        #print("term1:", term1)
        
        #term2 = pow(pk1, r, N_squared)
        # term2 = int(pk1**r % p)
        term2 = pow(int(pk1), r, int(p))

        r_sum = r_sum+r
        term2_test = int(term2_test*(int(term2)) % p)


        #print("r:", r)
        #term1 = term1 % N_squared
        #term2 = term2 % N_squared
        C_i = {"0": int(term1) , "1": int(term2)}
        '''
        1. 初始化和模运算
        term1 = integer(1) + X[i] * elgamal_params['N']
        这里将 integer(1) 和 X[i] * elgamal_params['N'] 相加。
        term2 = pow(pk1, r, N_squared)
        这里使用了模幂运算，直接在 N_squared 模数下计算 pk1^r。
        term1 = term1 % N_squared
        将 term1 约简到 N_squared 的模数范围内。
        term2 = term2 % N_squared
        同样将 term2 约简到 N_squared 的模数范围内。
        C_i = (term1 * term2) % N_squared
        最后将 term1 和 term2 相乘，并再次约简到 N_squared 的模数范围内。
        2. 对结果精度的影响
        模运算不会丢失信息：模运算的结果是唯一的余数，它不会丢失信息，只是将结果限制在一个有限域内。因此，在密码学中，模运算是非常常见的操作，用于确保数值在可处理的范围内，同时保持其数学性质。
        大整数运算的精度：Python 的 integer 类型（或 int 类型）可以处理任意大小的整数，因此在理论上，只要你的计算机内存足够，你可以处理非常大的整数而不会丢失精度。
        浮点数 vs 整数：如果你使用的是整数运算（如这里的模运算），则不会出现浮点数运算中的舍入误差问题。整数运算在 Python 中是精确的。
        '''

        #print(f"C_i = {C_i}")
        C.append(C_i)

    #print("term2_test", int(term2_test))
    #print("r_sum", int(r_sum))
    #print("PK1**r_sum", int(pk1**r_sum % p))

    return (C) 

def Decrypt(master_public_key: List[ElGamalKey], skf: integer, master_secret_key3: List[ElGamalKey], C: List[integer], y: List[int], N: integer) -> integer:
    N_squared = integer(N ** 2)
    pk1 = master_public_key['h']

    # 计算 c2 = ∏ C_i^y_i mod N^2
    c32 = 1
    c42 = 1
    for i in range(len(C)):
        c31 = C[i]['0'] ** y[i]  
        #print("c31", c31)
        c32 = (int(c32) * int(c31)) 
        c32 = c32 % N_squared
        
        
        c41 = C[i]['1']** y[i] 
        c42 = int(c42*(int(c41)) % p)
        

    # 计算 pk1^(-skf) mod N^2
    print("c42:",int(c42))
    #pk1_inv_skf = 1/ int(pk1**skf % p)
    
    print("int(pk1**skf % p) ",int(pk1**skf % p) )
    # 计算 E = (c2 * pk1_inv_skf) mod N^2
    E1 = (int(c42) // int(pk1**skf % p))
    #print("E1 is:", int(E1))
    
    
    E2 =  int(c32) % N_squared
    #print("E is:", int(E2))
    

    # 计算 result = (E - 1) // N
    result = (int(E2) - 1) // N  # 由于 E ≡ (1 + result * N) mod N^2

    return int(result)
