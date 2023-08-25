import pandas as pd
from sklearn import metrics

# Loading data from a .csv file.
data = pd.read_csv('metrics.csv')

# Split the data into two columns.
lClass = data['classe corretta']
classPrediction = data['classe predetta']

# Calculating accuracy
acc = metrics.accuracy_score(lClass, classPrediction)
print("Accuracy:", acc)
# Calculating precision
precision = metrics.precision_score(lClass, classPrediction)
print("Precision:", precision)
# Calculating recall
recall = metrics.recall_score(lClass, classPrediction)
print("Recall:", recall)
# Calculating F1-score
f1 = metrics.f1_score(lClass, classPrediction)
#f1 = 2*precision*recall/(precision+recall)
print("F1-score:", f1)
