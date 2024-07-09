from flask import Flask, render_template, request
from js_obfuscator import obfuscate_js

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        js_code = request.form['js_code']
        secret_key = request.form['secret_key']
        obfuscated_code = obfuscate_js(js_code, secret_key)
        return render_template('index.html', js_code=js_code, obfuscated_code=obfuscated_code)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
