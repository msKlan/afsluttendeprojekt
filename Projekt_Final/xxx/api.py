import flask
from flask import request, jsonify
import GetPhishingFeatures as gpf

app = flask.Flask(__name__)
app.config["DEBUG"] = True


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


@app.route('/', methods=['GET'])
def home():
    return '''<h1>Predict phishing</h1>'''

# En route for at teste url for phishing
@app.route('/predict', methods=['GET'])
def predict():
    query_parameters = request.args
    url = query_parameters.get('url')
    # features = gpf(url, 1)
    features = ""
    return '<h1>' + url + ' ' + features + ' is Phishing</h1>'


app.run()
