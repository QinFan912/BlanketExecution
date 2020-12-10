import operator

import numpy as np


class VarlablesValueKNN:
    def __init__(self, test_path, data_path):
        self.test_path = test_path
        self.data_path = data_path

        self.dataName = []
        self.dataValue = []
        self.test_data = []
        self.distance = dict()
        self.sorted_distance = dict()

        self.similar = dict()
        self.sorted_similar = dict()

        # self.calculate_distance()
        self.calculate_similar_value()

    def load_data(self):
        with open(self.data_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t')
            self.dataName.append(dataline[0])

            l = []
            for i in dataline[1:]:
                l.append(int(i))
            self.dataValue.append(l)

    def load_test_data(self):
        with open(self.test_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t')
            if 'main' in dataline[0]:
                l = []
                for i in dataline[1:]:
                    l.append(int(i))
                self.test_data = l

    def calculate_distance(self):
        self.load_data()
        self.load_test_data()

        # self.normalized_data(self.test_data)
        # self.normalized_data(self.dataValue)

        test_array = np.array(self.test_data)
        for index, d in enumerate(self.dataValue):
            train_array = np.array(d)
            dis = np.sqrt(np.sum(np.power((train_array - test_array), 2)))
            self.distance[self.dataName[index]] = dis

        self.sorted_distance = sorted(self.distance.items(), key=lambda x: x[1])

    def calculate_similar_value(self):
        self.load_data()
        self.load_test_data()

        for index, data_list in enumerate(self.dataValue):
            count = 0
            for v in self.test_data:
                if v in data_list:
                    count += 1
            self.similar[self.dataName[index]] = round(count/len(self.test_data), 3)
        self.sorted_similar = sorted(self.similar.items(), key=lambda  x: x[1], reverse=True)

    def normalized_data(self, arr):
        maxValue = np.max(arr)
        minValue = np.min(arr)
        for index, i in enumerate(arr):
            arr[index] = (i - minValue) / (maxValue - minValue)


if __name__ == '__main__':
    test_path = '/home/qinfan/PycharmProjects/angr/data/X86/rm_data.txt'

    data_path = '/home/qinfan/PycharmProjects/angr/data/MIPS32/rm_data.txt'
    knn = VarlablesValueKNN(test_path, data_path)
    # print(knn.dataValue)
    # print(knn.dataName)
    print(knn.similar)
    print(knn.similar['rm@main'])
    print(knn.sorted_similar)
