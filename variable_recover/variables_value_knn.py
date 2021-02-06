import operator
from collections import defaultdict
from math import log

import numpy as np


class VarlablesValueKNN:
    def __init__(self, test_path, data_path):
        self.test_path = test_path
        self.data_path = data_path

        self.dataName = []
        self.dataValue = []
        self.dataValueWeight = defaultdict(list)

        self.testData = []
        self.testDataWeight = []

        self.weight = dict()

        self.distance = dict()
        self.sorted_distance = dict()

        self.similar = dict()
        self.sorted_similar = dict()

        self.varNum = defaultdict(int)
        self.valueInVar = defaultdict(dict)

        # self.calculate_distance()
        self.weight_setting()
        self.calculate_similar_value()

    def load_data(self):
        with open(self.data_path) as f:
            datas = f.readlines()

        for data in datas:
            dataline = data.strip().split('\t' * 2)
            self.dataName.append(dataline[0])

            self.varNum[dataline[0]] = len(dataline[1:])

            for v in dataline[1:]:
                for i in v.strip().split('\t'):
                    self.dataValueWeight[dataline[0]].append(i)
                    self.dataValue.append(i)

            for i in set(self.dataValueWeight[dataline[0]]):
                for v in dataline[1:]:
                    if i in v.strip().split('\t'):
                        self.varNum[dataline[0] + str(i)] += 1
                        # self.valueInVar[dataline[0]][i] += 1

    def load_test_data(self):
        with open(self.test_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t' * 2)
            if '@main' in dataline[0]:
                l = []
                for v in dataline[1:]:
                    for i in v.strip().split('\t'):
                        l.append(i)
                    self.testData = list(set(l))
                    self.testDataWeight = l

    '''    
    def calculate_distance(self):
        self.load_data()
        self.load_test_data()

        # self.normalized_data(self.test_data)
        # self.normalized_data(self.dataValue)

        test_array = np.array(self.testData)
        for index, d in enumerate(self.dataValue):
            train_array = np.array(d)
            dis = np.sqrt(np.sum(np.power((train_array - test_array), 2)))
            self.distance[self.dataName[index]] = dis

        self.sorted_distance = sorted(self.distance.items(), key=lambda x: x[1])
    '''

    def calculate_similar_value(self):
        for index, data_list in self.dataValueWeight.items():
            count = 0
            for v in self.testData:
                if v in data_list:
                    count += self.weight[index + str(v)]
            self.similar[index] = count  # round(count / len(self.testData), 3)
        self.sorted_similar = sorted(self.similar.items(), key=lambda x: x[1], reverse=True)

    def weight_setting(self):
        self.load_data()
        self.load_test_data()

        dataSet = set(self.dataValue)
        total = len(self.dataValue)
        totalWeight = defaultdict(int)
        countDict = dict()

        for index in self.dataName:
            for i in self.dataValueWeight[index]:
                countDict[i] = self.dataValue.count(i)
                self.weight[index + str(i)] = round(
                    ((total - countDict[i]) / total) * log(self.varNum[index] / self.varNum[index + str(i)]), 4)
                totalWeight[index] += self.weight[index + str(i)]
        print(totalWeight)

        for index in self.dataName:
            for i in self.dataValueWeight[index]:
                countDict[i] = self.dataValue.count(i)
                self.weight[index + str(i)] = round(
                    ((total - countDict[i]) / total) * log(self.varNum[index] / self.varNum[index + str(i)]) / (totalWeight[index]), 4)
            # countDict = sorted(countDict.items(), key=lambda x: x[1], reverse=True)
        print(countDict)


if __name__ == '__main__':
    test_path = '/home/qinfan/PycharmProjects/angr/data/ARM32/false_data.txt'
    data_path = '/home/qinfan/PycharmProjects/angr/data/X86/false_data.txt'

    knn = VarlablesValueKNN(test_path, data_path)

    print(knn.testData)
    print(knn.testDataWeight)
    print(knn.dataValue)
    print(knn.dataValueWeight)
    print(knn.weight)

    print("knn similarity:", knn.similar['false@main'])
    print("knn similarity:", knn.similar['false@usage'])
    # print("knn similarity:", knn.similar['false@unexpand'])

    print(knn.varNum)
    print(knn.valueInVar)

    x = 0
    for i in knn.weight:
        x += knn.weight[i]
    print(x)


'''
    data_path1 = '/home/qinfan/PycharmProjects/angr/data/ARM32/rm_data.txt'
    data_path2 = '/home/qinfan/PycharmProjects/angr/data/ARM32/rm_data-O2.txt'
    data_path3 = '/home/qinfan/PycharmProjects/angr/data/ARM32/rm_data-O3.txt'

    data_path4 = '/home/qinfan/PycharmProjects/angr/data/X86/rm_data.txt'
    data_path5 = '/home/qinfan/PycharmProjects/angr/data/X86/rm_data-O2.txt'
    data_path6 = '/home/qinfan/PycharmProjects/angr/data/X86/rm_data-O3.txt'

    knn1 = VarlablesValueKNN(test_path, data_path1)
    knn2 = VarlablesValueKNN(test_path, data_path2)
    knn3 = VarlablesValueKNN(test_path, data_path3)
    knn4 = VarlablesValueKNN(test_path, data_path4)
    knn5 = VarlablesValueKNN(test_path, data_path5)
    knn6 = VarlablesValueKNN(test_path, data_path6)

    print("knn1 similarity:", knn1.similar['rm@main'])
    print("knn2 similarity:", knn2.similar['rm@main'])
    print("knn3 similarity:", knn3.similar['rm@main'])
    print("knn4 similarity:", knn4.similar['rm@main'])
    print("knn5 similarity:", knn5.similar['rm@main'])
    print("knn6 similarity:", knn6.similar['rm@main'])

    print("@@" * 100)
    path1 = '/home/qinfan/PycharmProjects/angr/data/MIPS32/rm_data-O2.txt'
    path2 = '/home/qinfan/PycharmProjects/angr/data/MIPS32/rm_data-O3.txt'

    k1 = VarlablesValueKNN(test_path, path1)
    k2 = VarlablesValueKNN(test_path, path2)

    print(k1.similar['rm@_ftext'])
    print(k2.similar['rm@_ftext'])

    print(k1.testData)
    print(len(k1.testData))
'''

# print(knn1.test_data)
# print(knn1.dataValue)
# print(knn1.dataName)
# print(knn1.similar)
# print(knn1.similar['rm@main'])
# print(knn1.sorted_similar)

# print("@@" * 50)
# knn2 = VarlablesValueKNN(test_path, data_path2)
# print(knn2.test_data)
# print(knn2.dataValue)
# print(knn2.dataName)
# print(knn2.similar)
# print(knn2.similar['rm@main'])
# print(knn2.sorted_similar)
