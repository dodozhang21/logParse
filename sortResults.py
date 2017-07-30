class Result:
    def __init__(self, count, ipAddress, key):
        self.count = count
        self.ipAddress = ipAddress
        self.key = key


def compare(a, b):
    x = a.ipAddress
    y = b.ipAddress
    return (-1 if (x < y) else (1 if (x > y) else 0))


listOfResults = [{'count': 4, 'ipAddress': '10.55.0.9', 'key': '10.55.0.9       a0b3.cc9d.7b22      '},
{'count': 4, 'ipAddress': '10.72.73.2', 'key': '10.72.73.2      0080.4544.f6b2      '},
{'count': 2, 'ipAddress': '10.50.28.2', 'key': '10.50.28.2      0090.c2e7.7da8      '},
{'count': 2, 'ipAddress': '10.73.29.2', 'key': '10.73.29.2      3c4a.92b8.1471      '},
{'count': 4, 'ipAddress': '10.75.6.2', 'key': '10.75.6.2       7848.59b9.ee50      '},
{'count': 6, 'ipAddress': '10.24.247.2', 'key': '10.24.247.2     a48d.3bc0.afbc      '},
{'count': 3, 'ipAddress': '10.72.80.3', 'key': '10.72.80.3      984b.e13b.ac82      '},
{'count': 9, 'ipAddress': '10.55.0.6', 'key': '10.55.0.6       001a.a0c8.16a5      '}]

printableResults = []
for item in listOfResults:
    printableResults.append(Result(item['count'], item['ipAddress'], item['key']))

printableResults.sort(compare)

for result in printableResults:
    print result.key + ' ' + str(result.count)

