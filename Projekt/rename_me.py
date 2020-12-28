import pickle
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import sys
from GetPhishingFeatures import GetPhishingFeatures
from os import system, name
import argparse
system('cls')

if __name__ == "__main__":
  
    parser = argparse.ArgumentParser(description="""
    This script test URLs for Phishing features.
    """)
      
    classifier = RandomForestClassifier()
    # classifier = pickle.load(open("RandomForest.sav", 'rb'))
    # print(classifier)


    
    parser.add_argument("-u", help="URL")
    parser.add_argument("-i", help="Input filename")

    args = parser.parse_args()
    url = args.u
    input_file = args.i
    # url = "https://www.dr.dk" #test url
    
    # test_input = GetPhishingFeatures(url) #get features af url
    # print(test_input)  
    # data_set = np.array(test_input).reshape(1, -1)[0]
    # print(data_set)  
    if (url):
        print(GetPhishingFeatures.GetPhishingFeatures(url))
    
    if (input_file):
        print("Input filename : ", input_file)
        
        with open(input_file, encoding="utf8") as fi, open("data.res", "w") as fo:
            Lines = fi.readlines()
            for line in Lines:
                fo.write("{}\n".format(
                    ','.join(map(str, GetPhishingFeatures.GetPhishingFeatures(line.strip())))))
                print("url {}\n{}".format(line.strip(),
                                          GetPhishingFeatures.GetPhishingFeatures(line.strip())))

        
    # print(classifier.predict(data_set))
    # predictions = classifier.predict(test_input)
 