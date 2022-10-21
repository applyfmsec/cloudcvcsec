import numpy as np
from matplotlib import pyplot as plt
import csv
#

def plot_enum():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []


    #x_data, y_data, z_data = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    s4 = plt.scatter(data_size, q_imply_p,c='c')
    plt.legend([s1, s2, s3, s4], ['cvc5 Data load', 'cvc5 SMT Encoding', 'cvc5 P => Q', 'cvc5 Q => P'])
    #plt.legend([s1, s2, s3, s4], ['z3 Data load', 'z3 SMT Encoding', 'z3 P => Q', 'z3 Q => P'])
    #plt.title('StringRe with wildcard')
    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()

#plot_enum()

def plot_string_re_wc():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    #q_imply_p = []

    data_size, data_load, smt_encoding, p_impy_q  = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size, data_load,c='r') # data load
    s2 = plt.scatter(data_size, smt_encoding,c='b')
    s3 = plt.scatter(data_size, p_impy_q,c='g')
    plt.legend([s1,s2,s3],['cvc5 Data load','cvc5 SMT Encoding','cvc5 P => Q' ])
    #plt.scatter(data_size, q_imply_p,c='c')
    #plt.title('StringRe with wildcard')
    plt.title('StringRe with WildCard Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()
plot_string_re_wc()

def plot_enum_combined():

    data_size = []
    data_load = []
    smt_encoding = []
    p_impy_q = []
    q_imply_p = []


    #x_data, y_data, z_data = np.loadtxt('string_re_wc_results.csv', delimiter=',', unpack=True)
    data_size, data_load, smt_encoding, p_impy_q, q_imply_p  = np.loadtxt('enum_results.csv', delimiter=',', unpack=True)
    z3_data_size, z3_data_load, z3_smt_encoding, z3_p_impy_q, z3_q_imply_p = np.loadtxt('z3_enum_results.csv', delimiter=',', unpack=True)

    s1 = plt.scatter(data_size[0:136], data_load[0:136],c='r') # data load
    s2 = plt.scatter(data_size[0:136], smt_encoding[0:136],c='b')
    s3 = plt.scatter(data_size[0:136], p_impy_q[0:136],c='g')
    s4 = plt.scatter(data_size[0:136], q_imply_p[0:136],c='c')

    s11 = plt.scatter(z3_data_size, z3_data_load, c='r', marker='+')  # data load
    s21 = plt.scatter(z3_data_size, z3_smt_encoding, c='b', marker='+')
    s31 = plt.scatter(z3_data_size, z3_p_impy_q, c='g', marker='+')
    s41 = plt.scatter(z3_data_size, z3_q_imply_p, c='c', marker='+')
    plt.legend([s1,s2,s3,s4, s11, s21, s31, s41], ['cvc5 Data load', 'cvc5 SMT Encoding', 'cvc5 P => Q', 'cvc5 Q => P', 'z3 Data load', 'z3 SMT Encoding', 'z3 P => Q', 'z3 Q => P'])
    #plt.title('StringRe with wildcard')
    plt.title('StringEnum Scalability')
    plt.xlabel('Datasize (n)')
    plt.ylabel('Time in secs')
    plt.show()
#plot_enum_combined()