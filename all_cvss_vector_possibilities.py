from random import choice
from cvss import CVSS3

av = ("N","A","L","P")
ac = ("L","H")
pr = ("N","L","H")
ui = ("N","R")
s = ("U","C")
c = ("N","L","H")
i = ("N","L","H")
a = ("N","L","H")

possibilites = []
counter = 0
while counter < 30000:
    counter += 1
    vector = f"CVSS:3.1/AV:{choice(av)}/AC:{choice(ac)}/PR:{choice(pr)}/UI:{choice(ui)}/S:{choice(s)}/C:{choice(c)}/I:{choice(c)}/A:{choice(a)}"
    if vector not in possibilites:
        possibilites.append(vector)
scores = {}
for vector in possibilites:
    score = CVSS3(vector).scores()[0]
    if score not in scores:
        scores[score] = [vector]
    else:
        scores[score].append(vector)
for vector in scores:
    scores[vector].sort()
scores = dict(sorted(scores.items()))