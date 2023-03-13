import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV

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
    print("False positive:", false_positive)
    print("True positive:", true_positive)
    print("False negative:", false_negative)
    print("True negative:", true_negative)
    print("----------------------------------------------")
    print("Overall score:", model.score(test_features, test_labels))
    print("Good detect:", (true_negative + true_positive), "Procentages: ",((true_negative + true_positive) / float(len(test_features)))*100, "%" )
    print("Bad detect:", (false_negative + false_positive), "Procentages: ",((false_negative + false_positive) / float(len(test_features)))*100, "%")
    print("Test data length:", len(test_features))

def crossvalidation(model, data_train, labels, cv):
    score = cross_val_score(model, data_train, labels, cv=cv, scoring='accuracy', n_jobs=-1, error_score='raise') 
    print(f"Crossvalidation with {cv} folds has score ", np.mean(score))

def load_dataset(path1, path2):
    # Load normal and malicious datasets 
    df_normal = pd.read_csv(path1)
    df_malware = pd.read_csv(path2)
    # Append them together
    df = df_normal.append(df_malware)
    return df

def data_preproccessing(df : pd.DataFrame):
    # Specify which columns to use for our model
    cols = ['Flow id', 'Duration', 'Received bytes','Received packets'
    ,'Transmitted bytes', 'Transmitted packets', 'Protocol', 
    'Application protocol', 'Total bytes', 'Total packets', 'label']

    df = df[cols]
    # Rename values in label column
    # Malware = 1
    # Normal = 0
    df.loc[df['label'] == 'normal', 'label'] = 0
    df.loc[df['label'] == 'malware', 'label'] = 1
    df['label'] = df['label'].astype('int64')
    #df['Port'] = df['Dst port']
    # Remove unwanted application protocol
    df = df[df['Application protocol'] != 'ntp']

    # Find the biggest number in the column and divide the rest of the
    # values with it
    norm_cols = ['Duration', 'Received bytes', 'Received packets',
    'Transmitted bytes', 'Transmitted packets', 'Total bytes',
    'Total packets']
    max_vals = df.max()

    for col in norm_cols:
        df[col] /= max_vals[col]

    # Performe one-hot encoding on categorical features
    df = pd.get_dummies(df)

    return df

def split_data(df : pd.DataFrame):
    # Extract labels which are the values we want to predict
    # And remove them from the dataframe
    labels = np.array(df['label'])
    df = df.drop('label', axis=1)

    # Save feature names for later use
    names = list(df.columns)

    # Finally convert to np array
    data = np.array(df)

    # Spliting data into traning and test data
    train_data, test_data, train_labels, test_labels = train_test_split(data, 
                                        labels, test_size = 0.2)

    print('Training Features Shape:', train_data.shape)
    print('Training Labels Shape:', train_labels.shape)
    print('Testing Features Shape:', test_data.shape)
    print('Testing Labels Shape:', test_labels.shape)

    return train_data, test_data, train_labels, test_labels


if __name__ == "__main__":

    df = load_dataset('dataset.csv', 'dataset2.csv')
    df = data_preproccessing(df)
    train_data, test_data, train_labels, test_labels = split_data(df)
    # Random forest classification
    # Instantiate model with 60 decision trees

    rf_model = RandomForestClassifier(n_estimators=60, max_depth=120, min_samples_leaf=2, min_samples_split=2)

    # Crosvalidation
    crossvalidation(rf_model, train_data, train_labels, 15)
    crossvalidation(rf_model, train_data, train_labels, 10)
    crossvalidation(rf_model, train_data, train_labels, 5)

    # Train model on training data
    rf_model.fit(train_data, train_labels)

    # Evaluate results
    evaluate_results(rf_model, test_data, test_labels)


#param_grid = {
#    'bootstrap' : [True], 
#    'max_depth':[120],
#    'max_features':[14, 16],
#    'min_samples_leaf':[2],
#    'min_samples_split':[2,3,4],
#    'n_estimators':[40,60,80]}
#
#rf = RandomForestClassifier()
#
#grid_search = GridSearchCV(estimator=rf,param_grid=param_grid,cv=5,n_jobs=-1, verbose=2)
#grid_search.fit(train_features, train_labels)
#
#print(grid_search.best_params_)