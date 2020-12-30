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
                l.append(i)
            self.dataValue.append(list(set(l)))

    def load_test_data(self):
        with open(self.test_path) as f:
            datas = f.readlines()
        for data in datas:
            dataline = data.strip().split('\t')
            if '_ftext' in dataline[0]:
                l = []
                for i in dataline[1:]:
                    l.append(i)
                self.test_data = list(set(l))

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
            self.similar[self.dataName[index]] = round(count / len(self.test_data), 3)
        self.sorted_similar = sorted(self.similar.items(), key=lambda x: x[1], reverse=True)

    def normalized_data(self, arr):
        maxValue = np.max(arr)
        minValue = np.min(arr)
        for index, i in enumerate(arr):
            arr[index] = (i - minValue) / (maxValue - minValue)


if __name__ == '__main__':
    test_path = '/home/qinfan/PycharmProjects/angr/data/MIPS32/rm_data-O3.txt'

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

    print(k1.test_data)
    print(len(k1.test_data))

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
