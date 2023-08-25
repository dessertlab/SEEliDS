from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from sklearn import metrics
import pandas as pd
import numpy as np
from sklearn.metrics import pairwise_distances

# Load data from CSV file and inherent only benign traffic.
df_X = pd.read_csv('LegitimateDataset.csv')

# I select the columns I want to use for clustering (all except 'class' since the data are not labeled). 
X = df_X.drop('Class', axis=1)

print("\n")

# I choose the number of clusters via the Silhoulette score, which indicates a measure of how well the points in a dataset are assigned to their cluster relative to neighboring clusters)
scores = []
for k in range(3, 15):
    kmeans = KMeans(n_clusters=k, n_init=100)
    kmeans.fit(X)
    score = silhouette_score(X, kmeans.labels_)
    scores.append(score)
    print(f"With {k} cluster I have a Silhoulette score of {score} \n")

print("\n")       
best_k = scores.index(max(scores)) + 3
print(f"The best value occurs with a number of clusters equal to: {best_k} \n")

# I initialize the KMeans object with the optimal cluster number provided by the Silhoulette score.
kmeans_X = KMeans(n_clusters=best_k, n_init=100)

# Addestro il modello utilizzando i dati letti
kmeans_X.fit(X)

# I predict which clusters the data points belong to using the trained model.
predictions_X = kmeans_X.predict(X)

# Calculate the distance of the points from the centroids of all clusters present.
distances_X = pairwise_distances(X, kmeans_X.cluster_centers_, metric='euclidean')

# I choose a threshold based on the maximum value of the distance between the data points and its centroid for each cluster.
distanceCluster_X = []
cluster_centroid = kmeans_X.cluster_centers_
print(type(cluster_centroid))

dfC = pd.DataFrame(cluster_centroid)
dfC.to_csv('centroids.csv', index=False)


for i in range(len(X)):
    distanceCluster_X.append(np.min(distances_X[i,:]))
threshold = max(distanceCluster_X)

print("The value of the threshold is: ",threshold)

