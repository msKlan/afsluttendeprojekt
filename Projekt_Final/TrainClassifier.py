from sklearn import tree
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
import argparse
from GetPhishingFeatures import GetPhishingFeatures as gpf
import pickle
import numpy as np
import sys


def load_train_save(classifier, p_file):
    '''
    Hent træningsdata og træn classifier'en, gem model og udkriv dens nøjagtigheds-skore
    '''
    # Hent træningsdata fra datafil
    training_data = np.genfromtxt(p_file, delimiter=',', dtype=np.int32)

    # Adskild input træningsdata fra datasæt
    input_data = training_data[:, :-1]

    # Adskild resultat datasæt fra datasæt
    output_data = training_data[:, -1]

    train_inputs, test_inputs, train_outputs, test_outputs = train_test_split(
        input_data, output_data, test_size=0.33)

    # Træn Random Forest (RF) classifier'en og udskriv dens parametre
    classifier.fit(train_inputs, train_outputs)

    # Tag test-datasættet til at lad RF forudsige resultat
    predictions = classifier.predict(test_inputs)

    # Udskriv nøjagtigheden af den forusigelser i % i forhold til hvad den burde være
    accuracy = 100.0 * accuracy_score(test_outputs, predictions)
    print(f"Nøjagtigheden af Random Forest er: {accuracy}")

    # Træn RF classifier'en med fuld datasæt
    classifier.fit(input_data, output_data)

    # Gem RF modellen i en model-fil
    pickle.dump(classifier, open('randomforest.mod', 'wb'))
    print("Random Forest model saved in 'randomforest.mod")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="""
    This script reads Phishing features and trains a Random Forest classifier.
    """)
    parser.add_argument(
        "-u", help="URL: Load saved Random Forest model and test aginst Phishing features exctraced from a single URL - and return result Phishing/not Phishing with probablities")
    parser.add_argument(
        "-t", help="Training data file: Read training data from file, train the Random Forest claasifier and save model to file 'randomforest.mod'")
    parser.add_argument(
        "-f", help="File og URL's: Load saved Random Forest model and test URL's from file aginst Phishing features - and return result Phishing/not Phishing with probablities")
    args = parser.parse_args()
    url = args.u
    input_train = args.t
    input_file = args.f

    if (url):       # Der angivet -u <URL>
        # load the model from disk
        classifier = RandomForestClassifier(
            n_estimators=25, max_depth=15, max_leaf_nodes=15000)
        classifier = pickle.load(open('randomforest.mod', 'rb'))

        # Hent og adskild input målepunkter fra datasæt
        url_features = np.array(gpf(url, 1))[:-1]
        inp_data = url_features.reshape(1, -1)

        # Forudsig om URL er Phishing og sandsynligeheden
        print(classifier.predict(inp_data), classifier.predict_proba(inp_data))

    if (input_train):   # Der angivet -t <fil af træningsdata>
        classifier = RandomForestClassifier(
            n_estimators=25, max_depth=15, max_leaf_nodes=15000)
        load_train_save(classifier, input_train)

    if (input_file):
        # load the model from disk
        classifier = pickle.load(open('randomforest.mod', 'rb'))

        output_file = input_file.split(".")[0] + ".res"
        print("Input filename : ", input_file)
        print("Output filename : ", output_file)

        with open(input_file, encoding="utf8") as fi, open(output_file, "w") as fo:
            lines = fi.readlines()
            for line in lines:
                url = line.strip()
                url_features = np.array(gpf(url, 1))[:-1]
                inp_data = url_features.reshape(1, -1)
                fo.write(
                    f"Result {classifier.predict(inp_data)} Probability {classifier.predict_proba(inp_data)} for URL: {url}\n")
