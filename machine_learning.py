import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.metrics import f1_score, auc, roc_curve, confusion_matrix
from sklearn.model_selection import GridSearchCV

# Run using python3 random_forest.py

def evaluate_results(model, test_features, test_labels):
    # Use random forest methon on the test data
    results = model.predict(test_features)

    score = f1_score(y_true=test_labels, y_pred=results, labels=test_labels)
    fpr, tpr, _thresholds = roc_curve(test_labels, results)
    auc_score = auc(fpr, tpr)

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

    print("----------------------------------------------")
    print("RESULTS")
    print("----------------------------------------------")
    print("False positive:", false_positive, " (detected as malware but it's normal).")
    print("True positive:", true_positive, "(detected as malware and it's malware).")
    print("False negative:", false_negative, "(detected as normal but it's malware).")
    print("True negative:", true_negative, "(detected as normal and it's normal).")
    print("----------------------------------------------")
    print("F1 score: ",score)
    print("Overall score: ", model.score(test_features, test_labels))
    print("Good detect: ", (true_negative + true_positive), ". Percentages: ",((true_negative + true_positive) / float(len(test_features)))*100, "%" )
    print("Bad detect: ", (false_negative + false_positive), ". Percentages: ",((false_negative + false_positive) / float(len(test_features)))*100, "%")
    print("Test data length: ", len(test_features))
    print("Confusion matrix ", type(confusion_matrix(test_labels, results)))

    return score, round(auc_score, 2), model.score(test_features, test_labels)

def crossvalidation(model, data_train, labels, cv):
    score = cross_val_score(model, data_train, labels, cv=cv, scoring='accuracy', n_jobs=-1, error_score='raise') 
    print("----------------------------------------------")
    print("CROSSVALIDATION")
    print(f"Crossvalidation with {cv} folds has score ", np.mean(score))
    return np.mean(score)

def load_dataset(path1, path2):
    # Load normal and malicious datasets 
    df_normal = pd.read_csv(path1)
    df_malware = pd.read_csv(path2)
    # Append them together
    df = df_normal.append(df_malware)
    return df

def data_preproccessing(df : pd.DataFrame):
    # Specify which columns to use for our model
    cols = ['Duration', 'Received bytes','Received packets'
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
                                        labels, test_size = 0.25)

    print("----------------------------------------------")
    print("DATA SHAPE")
    print('Training Features Shape:', train_data.shape)
    print('Training Labels Shape:', train_labels.shape)
    print('Testing Features Shape:', test_data.shape)
    print('Testing Labels Shape:', test_labels.shape)

    return train_data, test_data, train_labels, test_labels


def perform(model, train_data, train_labels, test_data, test_labels, algorithm):
    print("----------------------------------------------") 
    print(algorithm)
    print("----------------------------------------------") 

    results = {}
    results['Algorithm'] = algorithm

    # Crosvalidation with K-Folds 15, 10 and 5
    results['score15'] = crossvalidation(model, train_data, train_labels, 15)
    results['score10'] = crossvalidation(model, train_data, train_labels, 10)
    results['score5'] = crossvalidation(model, train_data, train_labels, 5)

    # Train model on training data
    model.fit(train_data, train_labels)

    # Evaluate results
    results['F1 score'], results['AUC'], results['Accuracy'] = evaluate_results(model, test_data, test_labels)

    return results


def params(train_data, train_labels, model, param_grid):

    grid_search = GridSearchCV(estimator=model,param_grid=param_grid,cv=15,n_jobs=-1, verbose=2)
    grid_search.fit(train_data, train_labels)

    print(grid_search.best_params_)

def boxplot_dataframe(df : pd.DataFrame):
    num_list = ['Duration', 'Received bytes', 'Received packets',
               'Transmitted bytes', 'Transmitted packets', 'Total bytes',
                'Total packets'] 
    
    fig = plt.figure(figsize=(15,30))

    for i in range(len(num_list)):
        column = num_list[i]
        sub = fig.add_subplot(3, 3, i + 1)
        sns.boxplot(x='label', y=column, data=df)
        plt.show()

def confusion_matrix_graph(cm_list, model_list, show):
    fig = plt.figure(figsize=(19,12))
    for i in range(len(cm_list)):
        cm = cm_list[i]
        model = model_list[i]
        sub = fig.add_subplot(2,3,i+1).set_title(model)
        cm_plot = sns.heatmap(cm, annot=True, cmap='Blues_r', fmt="d")
        cm_plot.set_xlabel('Predicted Values')
        cm_plot.set_ylabel('Acctual Values')
    
    if show:
        plt.show()
    plt.savefig("img/matrixes.png")

def accuracy_graph(df, show):
    ## Show the results of each classifier in the graph
    result_df = df.sort_values('Accuracy', ascending=False)
    sns.set_style('darkgrid')
    fig, ax = plt.subplots(figsize=(16, 12))
    sns.barplot(data=result_df, x='Algorithm', y='Accuracy', ax=ax)

    if show:
        plt.show()
    plt.savefig("img/result.png")

   
if __name__ == "__main__":

    df = load_dataset('dataset.csv', 'dataset2.csv')
    #boxplot_dataframe(df)
    df = data_preproccessing(df)
    train_data, test_data, train_labels, test_labels = split_data(df)

    # Instantiate all the models
    # n_estimators=50, max_depth=130, min_samples_leaf=1, min_samples_split=3, oob_score=True
    model_list = ['Random Forest', 'K-Nearest neighbor', 'Decision Tree', 'Naive Bayes',
                'SVM', 'Xgboost']
    auc_list = []
    acc_list = []
    cm_list = []
    f1score_list = []

    model_pipeline = []
    model_pipeline.append(RandomForestClassifier(n_estimators=50, max_depth=140, min_samples_leaf=1, min_samples_split=2, oob_score=False))
    model_pipeline.append(KNeighborsClassifier(n_neighbors=22))
    model_pipeline.append(DecisionTreeClassifier())
    model_pipeline.append(GaussianNB())
    model_pipeline.append(SVC())
    model_pipeline.append(XGBClassifier(n_estimators=100, max_depth=15, colsample_bytree=0.5,
                gamma=1, learning_rate=0.1, reg_lambda=1, subsample=0.8, scale_pos_weight=1))


    # Create pandas dataframe for collecting the results
    result_df = pd.DataFrame(columns=['Algorithm', 'score15', 'score10', 'score5', 
                'F1 score', 'AUC', 'Accuracy'])
    i = 0
    for model in model_pipeline:
        # Train model on training data
        model.fit(train_data, train_labels)
        y_pred = model.predict(test_data)
        f1score_list.append(f1_score(y_true=test_labels, y_pred=y_pred, labels=test_labels))
        acc_list.append(model.score(test_data, test_labels))
        cm_list.append(confusion_matrix(test_labels, y_pred))
        fpr, tpr, _thresholds = roc_curve(test_labels, y_pred)
        auc_list.append(auc(fpr, tpr)) 
        print()
        print(f"Model {model_list[i]} accuracy is: {acc_list[i] * 100}%.\nWith {cm_list[i][0][1]} false positives.")
        print()
        i += 1

    result_df['Algorithm'] = model_list
    result_df['F1 score'] = f1score_list
    result_df['AUC'] = auc_list
    result_df['Accuracy'] = acc_list

    # Print confusion matrix graph
    confusion_matrix_graph(cm_list, model_list, False)            

    # Show accuracy graph of each model
    accuracy_graph(result_df, True)
