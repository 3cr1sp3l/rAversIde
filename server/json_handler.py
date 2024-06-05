
import json
import re


def extract_json(text):
    # Find the beginning of the JSON by looking for the first opening brace
    start = text.find('{')
    if start == -1:
        print("Aucun JSON trouvé.")
        return None

    # Count braces to identify the end of JSON
    stack = 0
    for i in range(start, len(text)):
        if text[i] == '{':
            stack += 1
        elif text[i] == '}':
            stack -= 1
        
        # When all braces are closed, the JSON is complete
        if stack == 0:
            try:
                json_data = json.loads(text[start:i+1])
                return json_data
            except json.JSONDecodeError as e:
                print("Erreur de décodage JSON:", e)
                return None

    print("JSON non terminé ou mal formaté.")
    return None


def extract_content_without_loading_json(input_string):
    pattern = r'"content":\s*"([^"]*)"'  # Pattern to capture the content between the quotes after “content”:
    matches = re.findall(pattern, input_string)
    concatenated_content = "".join(matches)  # Concatenate all content found
    return concatenated_content

def clean_invalid_json_with_comma(json_text):
    import re
    # Regular expression to detect a comma directly followed by a closing bracket or a closing brace
    # We use \s* to manage possible white spaces between commas and closures
    pattern = r',\s*(\]|\})'
    # Replace this pattern with a simple closing bracket or brace
    cleaned_text = re.sub(pattern, r'\1', json_text)
    return cleaned_text
