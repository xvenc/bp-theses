import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_predict

def evaluate_results(model, test_features, test_labels):

    # Use random forest methon on the test data
    results = model.predict(test_features)

    false_positive = 0  # 1 -> 0
    true_positive = 0   # 1 -> 1
    false_negative = 0  # 0 -> 1
    true_negative = 0   # 0 -> 0
    for i in range(len(test_features)):
        if results[i] == 1 and test_labels[i] == 0:
            false_positive += 1
        if results[i] == 1 and test_labels[i] == 1:
            true_positive += 1
        if results[i] == 0 and test_labels[i] == 1:
            false_negative += 1
        if results[i] == 0 and test_labels[i] == 0:
            true_negative += 1

    print("RESULTS")
    print("----------------------------------------------")
    print("false positive:", false_positive)
    print("true positive:", true_positive)
    print("false negative:", false_negative)
    print("true negative:", true_negative)
    print("----------------------------------------------")
    print("library detection:", model.score(test_features, test_labels))
    print("good detect:", (true_negative + true_positive), "Procentages: ",((true_negative + true_positive) / float(len(test_features)))*100, "%" )
    print("bad detect:", (false_negative + false_positive), "Procentages: ",((false_negative + false_positive) / float(len(test_features)))*100, "%")
    print("All connection:", len(test_features))

def crossvalidation(model, data_train, labels):
    score = cross_val_predict(model, data_train, labels, cv=5) 
    print("Crossvalidation")
    print(np.mean(score))

# Load normal and malicious datasets 
df_normal = pd.read_csv('dataset.csv')
df_malware = pd.read_csv('dataset2.csv')
# Append them together
df = df_normal.append(df_malware)

# Data preproccessing

# Specify which columns to use for our model
cols = ['Flow id', 'Duration', 'Received bytes','Received packets' ,'Transmitted bytes', 'Transmitted packets', 'Protocol', 'Application protocol', 'Total bytes', 'Total packets', 'label']
df = df[cols]
# Rename values in label column
# Malware = 1
# Normal = 0
df.loc[df['label'] == 'Normal', 'label'] = 0
df.loc[df['label'] == 'malware', 'label'] = 1
df['label'] = df['label'].astype('int64')
# Remove unwanted application protocol
df = df[df['Application protocol'] != 'ntp']

# TODO normalization
# Find the biggest number in the column and divide the rest of the
# values with it

max_values = df.max()

# Performe one-hot encoding on categorical features
df = pd.get_dummies(df)

# Extract labels which are the values we want to predict
# And remove them from the dataframe
labels = np.array(df['label'])
df = df.drop('label', axis=1)

# Save feature names for later use
names = list(df.columns)

# Finally convert to np array
data = np.array(df)

# Spliting data into traning and test data
train_features, test_features, train_labels, test_labels = train_test_split(data, 
                                    labels, test_size = 0.2, random_state = 42)

print('Training Features Shape:', train_features.shape)
print('Training Labels Shape:', train_labels.shape)
print('Testing Features Shape:', test_features.shape)
print('Testing Labels Shape:', test_labels.shape)

# Random forest classification

# Instantiate model with 500 decision trees
rf_model = RandomForestClassifier(n_estimators=500, random_state=42)

# Crosvalidation
crossvalidation(rf_model, train_features, train_labels)

# Train model on training data
rf_model.fit(train_features, train_labels)

# Evaluate results
evaluate_results(rf_model, test_features, test_labels)

