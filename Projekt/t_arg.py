import GetPhishingFeatures as gpf
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    This script test URLs for Phishing features.
    """)
    parser.add_argument("-u", help="URL")
    parser.add_argument("-i", help="Input filename")

    args = parser.parse_args()

    url = args.u
    input_f = args.i
    print(input_f)

    # url = "dr.dk" #test url

    if (url):
        print(gpf.GetPhishingFeatures(url))

    if (input_f):
        print("Input filename : ", input_f)

        with open(input_f, encoding="utf8") as fi, open("data.res", "w") as fo:
            Lines = fi.readlines()
            for line in Lines:
                fo.write("{}\n".format(
                    ','.join(map(str, gpf.GetPhishingFeatures(line.strip())))))
                print("url {}\n{}".format(line.strip(),
                                          gpf.GetPhishingFeatures(line.strip())))

        ''' Åbne input_f
			læs linje for linje
				CheckURLforPhishing(url) og output i en fil
		'''
