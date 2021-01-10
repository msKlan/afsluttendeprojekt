import flask
from flask import request, redirect
from urllib.parse import unquote
from GetPhishingFeatures import GetPhishingFeatures as gpf
from sklearn.ensemble import RandomForestClassifier
import pickle
import numpy as np

app = flask.Flask(__name__)
app.config["DEBUG"] = True


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


@app.route('/', methods=['GET'])
def home():
    return '''<h1>Predict phishing - try "http://127.0.0.1:5000/predict?url=http%3A%2F%2F006.zzz.com.ua" </h1>'''

# En route for at teste url for phishing
@app.route('/predict', methods=['GET'])
def predict():
    query_parameters = request.args
    url = unquote(query_parameters.get('url'))
    print(url)
    features = np.array(gpf(url, 1))[:-1]
    inp_data = features.reshape(1, -1)

    # Forudsig om URL er Phishing
    pred = classifier.predict(inp_data)
    print(pred[0])
    if (pred[0] == -1):
        return '<h1>This url: ' + url + ' is a phishing attempt!</h1>'
    else:
        return '<h1>To be redirected to ' + url + '</h1>'   # Udkommenter denne
        # return redirect(url)                              # og fjern kommentar på denne


# Start med at hente Random Forest Classifier modellen op
classifier = RandomForestClassifier(
    n_estimators=500, max_depth=15, max_leaf_nodes=15000)
classifier = pickle.load(open('randomforest.mod', 'rb'))

# Start og lyt på port 5000
app.run()

# http://127.0.0.1:5000/predict?url=https%3A%2F%2Fwww.dr.dk
# http://127.0.0.1:5000/predict?url=http%3A%2F%2F006.zzz.com.ua
