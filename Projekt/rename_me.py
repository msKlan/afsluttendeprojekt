import pickle
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import sys
from GetPhishingFeatures import GetPhishingFeatures as gpf
from os import system, name
import argparse
system('cls')

if __name__ == "__main__":
  
    parser = argparse.ArgumentParser(description="""
    This script test URLs for Phishing features.
    """)
    parser.add_argument("-u", help="URL")
    parser.add_argument("-i", help="Input filename")
    args = parser.parse_args()
    url = args.u
    input_file = args.i
     
    classifier = RandomForestClassifier()
    classifier = pickle.load(open("RandomForest.sav", 'rb'))
    # print(classifier)


    
   # url = "https://www.dr.dk" #test url
    
    # test_input = gpf(url, 1) #get features af url
    # print(test_input)  
    # data_set = np.array(test_input).reshape(1, -1)[0]
    # print(data_set)  
    if (url):
        data_set = gpf(url, 1)
        print(data_set)
        data_set = data_set[:-1]
        data_set = np.array(data_set).reshape(1,-1)
        print(classifier.predict(data_set))
        print(classifier.predict_proba(data_set))
        
        # print(gpf(url))
    
    if (input_file):
        print("Input filename : ", input_file)
        
        with open(input_file, encoding="utf8") as fi, open("data.res", "w") as fo:
            Lines = fi.readlines()
            for line in Lines:
                fo.write("{}\n".format(
                    ','.join(map(str, gpf(line.strip(), 1)))))
                # print("url {}\n{}".format(line.strip(),
                #                           gpf(line.strip())))

        
    # print(classifier.predict(data_set))
    # predictions = classifier.predict(test_input)
 