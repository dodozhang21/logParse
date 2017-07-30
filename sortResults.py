class Result:
    def __init__(self, count, ipAddress, key):
        self.count = count
        self.ipAddress = ipAddress
        self.key = key


def compare(a, b):
    x = a.ipAddress
    y = b.ipAddress
    return (-1 if (x < y) else (1 if (x > y) else 0))


listOfResults = [{'count': 4, 'ipAddress': '1.0.0.9',
                  'key': '1.0.0.9       abdc.abcd.7b22      '},
                 {'count': 4, 'ipAddress': '1.0.0.4',
                  'key': '1.0.0.4       sdg.asdg.f6b2       '},
                 {'count': 2, 'ipAddress': '7.89.0.2',
                  'key': '7.89.0.2      asydg.uyk.asdg      '},
                 {'count': 2, 'ipAddress': '3.4.0.2',
                  'key': '3.4.0.2       hjj.jkl.1471        '}]

printableResults = []
for item in listOfResults:
    printableResults.append(
        Result(item['count'], item['ipAddress'], item['key']))

printableResults.sort(compare)

for result in printableResults:
    print result.key + ' ' + str(result.count)

