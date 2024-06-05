
from flask import Flask, jsonify
from flask import request
import chromadb
from functionalities import RenameFunctionAndVariables, analyseWithRag, analyseWithoutRag, chatbot
from utils import *

# Initialize the Flask application
app = Flask(__name__)
apiKey = ""

@app.route('/')
def route_home():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RAversIde Server</title>
        <style>
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                font-family: Arial, sans-serif;
                background-color: #f0f0f0;
            }
            .message {
                text-align: center;
                font-size: 2em;
                color: #333;
                padding: 20px;
                border: 2px solid #333;
                border-radius: 10px;
                background-color: #fff;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            .link {
                margin-top: 20px;
                font-size: 1em;
                color: #007bff;
                text-decoration: none;
            }
            .link:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="message">
            Welcome to RAversIde Server!<br>
            <a class="link" href="https://github.com/EstebanbanC/rAversIde.git" target="_blank">Try our plugin!</a>
        </div>
    </body>
    </html>
    '''

@app.route('/analyze', methods=['POST'])
def analyse():
    try:
        # Retrieve data
        post_data = request.json

        is_rag = post_data.get('rag', False)

        response = ""

        # Analysis choice
        if is_rag:
            response = analyseWithRag(post_data)
        elif is_rag == False:
            response = analyseWithoutRag(post_data)
        else:
            return "Invalid rag parameter", 400

        if "No vulnerabilities detected" in str(response):
            return "No vulnerabilities detected"
        if "Unable to repair JSON" in str(response):
            return "Unable to repair JSON"
        try: 
            response = json.loads(response)
            for i in range(len(response['comment'])):
                if isinstance(response['comment'][i], list):
                    cvss_severity = get_cvss_severity(response['comment'][i][1])  # Retrieve CVSS severity for the CWEs detected
                    if cvss_severity is None:
                        cvss_severity = "unknown"
                    response['comment'][i] = response['comment'][i] + [cvss_severity] # Add CVSS severity to the json
                else:
                    print("Error: comment is not a list")
        except Exception as e:
            print("Erreur lors de l'ajout de la sévérité CVSS:", e)
            raise SystemExit("Arrêt du script en raison d'une erreur de décodage JSON.")
        return response
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}, 500


@app.route('/chatbot', methods=['POST'])
def root_chatbot():
    try:
        data = request.json
        response = chatbot(data) # Call the function to ask ai to answer the question
        return str(response)
    except Exception as e:
        return {"error": str(e)}, 500


@app.route('/renameVariableAndFunction', methods=['POST'])
def route_rename_variable_and_function():
    try:
        # Retrieve data
        data = request.json
        return RenameFunctionAndVariables(data) # Call the function to ask ai to propose new variables and functions names
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}, 500

#Delete the history of the conversation linked to an API key
@app.route('/clear', methods=['POST'])
def clear():
    try:
        # Retrieve data
        data = request.json
        
        if not data or "apiKey" not in data:
            return jsonify({"error": "Missing API key in request body"}), 400

        apiKey = data["apiKey"]
        client = chromadb.PersistentClient(path="chroma_db") 
        
        try:
            collection = client.get_collection(name=apiKey) 
        except Exception as e:
            print(f"Error fetching collection: {e}")
            return jsonify({"message": "History already clear"}), 200

        if collection:
            print("Collection exists, deleting...")
            client.delete_collection(name=apiKey)
            return jsonify({"message": "History cleared"}), 200
        else:
            return jsonify({"message": "History already clear"}), 200

    except Exception as e:
        return jsonify({"message": "Server error", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
  
