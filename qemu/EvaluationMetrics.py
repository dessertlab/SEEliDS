import pandas as pd
from sklearn import metrics

# Caricamento dei dati da un file .csv
data = pd.read_csv('metrics.csv')

# Dividi i dati in due colonne
lClass = data['classe corretta']
classPrediction = data['classe predetta']

# Calcolo l'accuracy
acc = metrics.accuracy_score(lClass, classPrediction)
print("Accuracy:", acc)
# Calcolo la precision
precision = metrics.precision_score(lClass, classPrediction)
print("Precision:", precision)
# Calcolo il recall
recall = metrics.recall_score(lClass, classPrediction)
print("Recall:", recall)
# Calcolo la F1-score
f1 = metrics.f1_score(lClass, classPrediction)
#f1 = 2*precision*recall/(precision+recall)
print("F1-score:", f1)
