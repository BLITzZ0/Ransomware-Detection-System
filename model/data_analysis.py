# %%
# Importing libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Loading the dataset
malData = pd.read_csv("MalwareData.csv", sep="|", low_memory=True)

# Dataset Overview
print(malData.head())
print(malData.shape)
print(malData.describe())

# Splitting into legit and malware
legit = malData[0:41323].drop(["legitimate"], axis=1)
mal = malData[41323::].drop(["legitimate"], axis=1)
print(f"The shape of the legit dataset is: {legit.shape[0]} samples, {legit.shape[1]} features")
print(f"The shape of the mal dataset is: {mal.shape[0]} samples, {mal.shape[1]} features")

# Plotting histogram
fig = plt.figure()
ax = fig.add_axes([0, 0, 1, 1])
ax.hist(malData['legitimate'], 20)
plt.show()

# Data Cleaning
y = malData['legitimate']
malData = malData.drop(['legitimate', 'Name', 'md5'], axis=1)
print("The Name and md5 variables are removed successfully")

# Splitting the dataset
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(malData, y, test_size=0.3, random_state=42)
print(X_train.shape, X_test.shape)



# %%
# Random Forest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix, f1_score, accuracy_score

clf = RandomForestClassifier(max_depth=2, random_state=0)
randomModel = clf.fit(X_train, y_train)

# Evaluation
train_pred = randomModel.predict(X_train)
print("Train Accuracy (Random Forest):", accuracy_score(y_train, train_pred))

prediction = randomModel.predict(X_test)
print("Test Accuracy (Random Forest):", accuracy_score(y_test, prediction))
print("F1 Score (Random Forest):", f1_score(y_test, prediction))

# Confusion Matrix
titles_options = [
    ("Confusion matrix, without normalization", None),
    ("Normalized confusion matrix", 'true')
]

for title, normalize in titles_options:
    disp = ConfusionMatrixDisplay.from_estimator(
        randomModel,
        X_test,
        y_test,
        display_labels=['malware', 'legitimate'],
        cmap=plt.cm.Blues,
        normalize=normalize
    )
    disp.ax_.set_title(title)
    print(title)
    print(disp.confusion_matrix)
    plt.show()



# %%
# Support Vector Machine (SVM)
from sklearn.svm import LinearSVC
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

pca = PCA(n_components=20)

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('pca', PCA(n_components=20)),
    ('svm', LinearSVC(random_state=0, max_iter=10000))
])

# Train the model
pipeline.fit(X_train, y_train)

# Evaluation
train_svm = pipeline.predict(X_train)
print("Train Accuracy (LinearSVC with PCA):", accuracy_score(y_train, train_svm))

pred = pipeline.predict(X_test)
print("Test Accuracy (LinearSVC with PCA):", accuracy_score(y_test, pred))
print("F1 Score (LinearSVC with PCA):", f1_score(y_test, pred))

# Confusion Matrix
for title, normalize in titles_options:
    disp = ConfusionMatrixDisplay.from_estimator(
        pipeline,
        X_test,
        y_test,
        display_labels=['malware', 'legitimate'],
        cmap=plt.cm.Blues,
        normalize=normalize
    )
    disp.ax_.set_title(title)
    print(title)
    print(disp.confusion_matrix)
    plt.show()



# %%
# Neural Network
import tensorflow as tf
from tensorflow.keras.models import Sequential  # type: ignore
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization  # type: ignore

print(tf.__version__)

model = Sequential()
model.add(Dense(32, input_dim=54, activation='relu'))
model.add(BatchNormalization())
model.add(Dropout(0.3))
model.add(Dense(16, activation='relu'))
model.add(Dropout(0.2))
model.add(Dense(1, activation='sigmoid'))

model.summary()

# Compile and train
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=5, batch_size=32, validation_split=0.2, class_weight={0:1, 1:5})

# Evaluation
trainPred = model.predict(X_train)
trainPred = [1 if y >= 0.5 else 0 for y in trainPred]
print("Train Accuracy (Neural Network):", accuracy_score(y_train, trainPred))

y_prediction = model.predict(X_test)
y_prediction = [1 if y >= 0.5 else 0 for y in y_prediction]
print("Test Accuracy (Neural Network):", accuracy_score(y_test, y_prediction))
print("F1 Score (Neural Network):", f1_score(y_test, y_prediction))

conf_matrix = confusion_matrix(y_test, y_prediction)
print("Confusion Matrix (Neural Network):")
print(conf_matrix)

# Add confusion matrix visualization
for title, normalize in titles_options:
    disp = ConfusionMatrixDisplay.from_predictions(
        y_test,
        y_prediction,
        display_labels=['malware', 'legitimate'],
        cmap=plt.cm.Blues,
        normalize=normalize
    )
    disp.ax_.set_title(title)
    print(title)
    print(disp.confusion_matrix)
    plt.show()

