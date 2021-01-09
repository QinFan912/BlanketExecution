import operator
from math import log

import numpy as np


class VarlablesValueKNN:
    def __init__(self, test_path, data_path):
        self.test_path = test_path
        self.data_path = data_path

        self.dataName = []
        self.dataValue = []
        self.dataValueWeight = []

        self.testData = []
        self.testDataWeight = []

        self.weight = dict()

        self.distance = dict()
        self.sorted_distance = dict()

        self.similar = dict()
        self.sorted_similar = dict()

        # self.calculate_distance()
        self.weight_setting()
        self.calculate_similar_value()

    def load_data(self):
        with open(self.data_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t')
            self.dataName.append(dataline[0])

            l = []
            for i in dataline[1:]:
                l.append(i)
                self.dataValueWeight.append(i)
            self.dataValue.append(list(set(l)))

    def load_test_data(self):
        with open(self.test_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t')
            if 'main' in dataline[0]:
                l = []
                for i in dataline[1:]:
                    l.append(i)
                self.testData = list(set(l))
                self.testDataWeight = l

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

    def calculate_similar_value(self):
        for index, data_list in enumerate(self.dataValue):
            count = 0
            for v in self.testData:
                if v in data_list:
                    count += self.weight[v]
            self.similar[self.dataName[index]] = count  # round(count / len(self.testData), 3)
        self.sorted_similar = sorted(self.similar.items(), key=lambda x: x[1], reverse=True)

    def weight_setting(self):
        self.load_data()
        self.load_test_data()

        dataSet = set(self.dataValueWeight)
        total = len(self.dataValueWeight)
        totalWeight = 0
        countDict = dict()

        # for i in dataSet:
        #     countDict[i] = self.dataValueWeight.count(i)
        #     self.weight[i] = round(((total - countDict[i]) / total) * log(total / (countDict[i] + 1)) / 10, 4)
        #     totalWeight += self.weight[i]
        # print(totalWeight)

        for i in dataSet:
            countDict[i] = self.dataValueWeight.count(i)
            self.weight[i] = round(
                (((total - countDict[i]) / total) * log(total / (countDict[i])) / 10), 4)
        countDict = sorted(countDict.items(), key=lambda x: x[1], reverse=True)
        print(countDict)


if __name__ == '__main__':
    test_path = '/home/qinfan/PycharmProjects/angr/data/X86/rm_data.txt'
    data_path = '/home/qinfan/PycharmProjects/angr/data/ARM32/rm_data.txt'

    knn = VarlablesValueKNN(test_path, data_path)

    print(knn.testData)
    print(knn.testDataWeight)
    print(knn.dataValue)
    print(knn.dataValueWeight)
    print(knn.weight)

    print(knn.weight["0"])
    print(knn.weight["1"])
    print(knn.weight["2"])
    print(knn.weight["rm"])

    print("knn similarity:", knn.similar['rm@main'])

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
