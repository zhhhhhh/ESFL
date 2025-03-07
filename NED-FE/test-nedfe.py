      
import src.inner_product.single_input_fe.elgamal_ip.nedfe
import numpy as np
import unittest


class TestElGamalInnerProduct(unittest.TestCase):

    def test_fin_result(self):

        # 分配公钥私钥
        fe = src.inner_product.single_input_fe.elgamal_ip.nedfe  # 函数y
        pk, sk, N = fe.set_up(1024, 5) # 调用edfe setup 算法，秘钥是1024位，5对密钥
        #TP
        pk1,sk1 = pk[0],sk[0]   # generator
        pk2,sk2 = [pk[1],pk[2],pk[3]], [sk[1],sk[2],sk[3]]  # Encryptor
        pk3,sk3 = pk[4],sk[4]   # decryptor

        y = [1, 1, 1]   # 聚合权重
        x = [3, 2, 3]   # 加密者的明文
        ctr=0  # 计数器，后面每次加1
        aux='edfe' # 改名字edfe

        # 秘钥 sk1: 生成器（Generator）的私钥。
        # pk2: 加密者（Encryptor）的公钥列表，用于加密数据。
        # sk2: 加密者的私钥列表，与 pk2 对应。
        # ctr: 计数器，通常用于防止重放攻击或确保每次派生的密钥唯一。
        # y: 聚合权重向量，用于定义聚合规则。
        # aux: 辅助信息字符串，可能用于标识或配置特定的加密环境
        skf = fe.KeyDerive(sk1,pk2,sk2,ctr,y,aux)   # 聚合过程中的函数秘钥，skf作用于聚合密钥
        #print(skf)

        # 加密局部模型（明文数据x），生成密文C_x
        # pk1: 生成器（Generator）的公钥。
        # sk2: 加密者的私钥列表，用于辅助加密过程。
        # pk3: 解密者（Decryptor）的公钥。
        # ctr: 计数器，确保每次加密的唯一性。
        # x: 明文数据向量，需要被加密的数据。
        # aux: 辅助信息字符串，可能用于标识或配置特定的加密环境。
        C_x = fe.Encrypt(pk1,sk2,pk3,ctr,x,aux,N)   # 数组   # 由客户端调用的加密算法加密局部模型
        #print(C_x)

        # 解密聚合后的密文，计算内积结果
        # pk1: 生成器（Generator）的公钥。
        # skf: 功能加密密钥，由 KeyDerive 方法生成，用于解密聚合后的密文。
        # sk3: 解密者的私钥。
        # C_x: 加密后的密文，由 Encrypt 方法生成。
        # y: 聚合权重向量，用于定义聚合规则。
        result = fe.Decrypt(pk1,skf,sk3,C_x,y,N)  # 内积
        print("NED-FE result is:", result)  # 改名字
       # obtained_inner_prod = fe.decrypt(pk, c_x, key_y, y, 2000)
        # 计算预期的内积结果，用于验证加密方案的正确性
        expected_inner_prod = np.inner(x, y)
        print("The correct result is:", expected_inner_prod)

if __name__ == "__main__":
    unittest.main()

    
