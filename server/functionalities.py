
import json
from utils import do_hf_call, get_new_api_key, getPromptFromFile, pretty_print_code


from llama_index.embeddings.jinaai import JinaEmbedding
import datetime

from typing import Any
import chromadb

# Handle a chatbot query using an embedding model to retrieve and generate responses based on historical context.
def chatbot(data, debug=False) -> str:
    
    # Initialize the database client
    client = chromadb.PersistentClient(path="chroma_db")
    apiKey = data["apiKey"]
    
    # Prepare the code context if provided
    if "code_c" in data:
        code_c = 'code : \n'.join(map(str, data["code_c"].values()))
    else:
        code_c = ""
        
    question = data["question"]

    # Initialize the Jina embedding model with a new API key
    jina_embedding_model = JinaEmbedding(
        api_key=get_new_api_key(),
        model="jina-embeddings-v2-base-code",
    )
    
    code_escaped = code_c.replace("{", "{{").replace("}", "}}")
    newConv = code_escaped + question
    
    # Generate embedding for the current conversation
    code_embedding = jina_embedding_model.get_query_embedding(newConv)
        
    # Attempt to retrieve the collection for the current API key, create if non-existent
    try:
        collection = client.get_collection(apiKey)

    except Exception as e:
        # Si la collection n'existe pas, créez-la
        print("Collection does not exist, creating new one.")
        collection = client.create_collection(name=apiKey)
        
    # Query for similar historical conversations based on embedding similarity
    similar_conversations = collection.query(
            query_embeddings=code_embedding,
            n_results=5
        )
    
    if (debug) : print("similar_conversations", similar_conversations)
    
    # Extract documents and their associated IDs from the results
    documents = similar_conversations['documents'][0]
    ids = similar_conversations['ids'][0]
    # Create a list of tuples (date, document) for sorting
    doc_with_dates = list(zip(ids, documents))

    # Sort by date 
    doc_with_dates.sort()

    # Concatenate documents for historical context
    historical_docs = "\n".join(doc[1] for doc in doc_with_dates)

    # Prepare the prompt for the Hugging Face model call
    qa_prompt_tmpl = getPromptFromFile("chatbot")
    qa_prompt_tmpl = qa_prompt_tmpl.replace("{question}", question)
    qa_prompt_tmpl = qa_prompt_tmpl.replace("{historique}", str(historical_docs))
    qa_prompt_tmpl = qa_prompt_tmpl.replace("{query_str}", str(code_escaped))
        
    # Query the language model using the prepared prompt
    print("Querying")
    result = do_hf_call(qa_prompt_tmpl, "chatbot", apiKey)
    
    # Add the current interaction to the collection for future context awareness
    addHistory = "this is in the history of the conversation\n" + "Previous question: " + str(question) + "\n" + "previous code: " + str(code_c) + "\n" + "Previous response: " + str(result) + "\n\n"
    embeddingHistory = jina_embedding_model.get_text_embedding(addHistory)
    now = datetime.datetime.now()
    datetime_str = now.strftime("%Y-%m-%d %H:%M:%S")
    collection.add(
        embeddings=embeddingHistory,
        documents=[addHistory],
        ids=str(datetime_str)
    )
    print("Indexing done")
    return str(result)


# Renames functions and variables in code using multi-turn with a language model
def RenameFunctionAndVariables(data, debug = False) -> Any:
    
    # Retrieve API key from data dictionary
    apiKey = data["apiKey"]
    
    # Prepare the initial prompt from file, injecting the decompiled code
    first_prompt = getPromptFromFile("rename_first_turn")
    first_prompt = first_prompt.replace("{code_decompile}", str(data["code_c"]))

    if (debug) : print(f"--- Prompt ---\n{first_prompt}")

    # Call the language model to interpret the code
    result = do_hf_call(first_prompt, "rename",apiKey, debug)

    if (debug) : print(f"--- FIRST TURN ----\n{result}")

    # Prepare the second prompt using the results of the first call
    second_prompt = getPromptFromFile("rename_second_turn")
    second_prompt = second_prompt.replace("{explication}", str(result))
    second_prompt = second_prompt.replace("{rename_list}", str(data["items"]))
    second_prompt = second_prompt.replace("{code_decompile}", str(data["code_c"]))
    if (debug) : print(f"--- Prompt ---\n{second_prompt}")
    
    # Call the language model to ask for new names
    result = do_hf_call(second_prompt, "rename",apiKey, debug)
    if (debug) : print(f"--- Final ---\n{result}")

    return result


# Analyzes code for vulnerabilities using a Jina embedding model and returns the results with associated metadata.
def analyseWithRag(post_data, debug = False):
    # Retrieve the API key and serialize the code content to JSON
    apiKey=post_data["apiKey"]
    
    # Convert JSON data to a pretty printed format for better readability in queries
    code_c_json = json.dumps(post_data['code_c'])
    code_c = pretty_print_code(code_c_json)
    
    # Initialize the database client and retrieve the specified collection
    client = chromadb.PersistentClient(path="chroma_db")
    collection = client.get_collection(name="quickstart")

    # Set up the Jina embedding model with a new API key
    embed_model = JinaEmbedding(
        api_key=get_new_api_key(),
        model="jina-embeddings-v2-base-code",
    )
    # Generate embeddings for the code
    embeddings = embed_model.get_query_embedding(code_c)

    # Query the collection for similar entries based on embeddings
    query = collection.query(
        query_embeddings=embeddings,
        n_results=5
    )
    query_parts = []
    
    # Process and format the query results
    for i, meta in enumerate(query['metadatas'][0]):
        cwe_id = meta['CWE-id']

        result_str = f"CWE-id: {query['metadatas'][0][i]['CWE-id']}, CWE-name: {query['metadatas'][0][i]['name']}, CWE-description: {query['metadatas'][0][i]['description']}"

        if query['metadatas'][0][i]['isVulnerable']:
            result_str += f", Warning: this code is vulnerable to CWE {cwe_id}\n"
        else:
            result_str += f", This code is not vulnerable, it is 100% secure to CWE {cwe_id}\n"
        result_str += f"code: {query['metadatas'][0][i]['code']}, IsVulnerable: {query['metadatas'][0][i]['isVulnerable']}"
        query_parts.append(result_str)

    # Concatenate individual query results into a single string
    concatenated_query = "\n".join(query_parts)
    context = json.dumps(concatenated_query, indent=2)

    # Prepare and execute the call to the language model
    analyze_prompt = getPromptFromFile("analyze")
    full_prompt = analyze_prompt.replace("{code}", code_c).replace("{information}", context)
    response = do_hf_call(full_prompt, "analyze", apiKey, True)
    if debug : print(f" --- Analyse with RAg - Response ---\n{response}")
    return response

#Analyzes code without using RAG, directly querying a language model
def analyseWithoutRag(post_data, debug = False):
    apiKey=post_data["apiKey"]
    code_c_json = json.dumps(post_data['code_c'])
    analyze_prompt = getPromptFromFile("analyzeWithoutRag")
    full_prompt = analyze_prompt.replace("{code}", code_c_json)

    response = do_hf_call(full_prompt, "analyze", apiKey)
    return response