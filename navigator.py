# search_chatgpt.py

import os
import openai
from dotenv import load_dotenv
import json

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()
api_key = os.environ.get('API_KEY')

openai.api_key = api_key

def search_chatgpt(prompt):
    response = openai.Completion.create(
        engine="gpt-3.5-turbo-instruct",
        prompt=prompt,
        temperature=0.7,
        max_tokens=1000
    )

    try:
        response_text = response.choices[0].text.strip()
    except json.JSONDecodeError as e:
        response_text = None

    return response_text

# main.py

import streamlit as st

# Importez la fonction de recherche
# from search_chatgpt import search_chatgpt

def main():
    st.title("Recherche basée sur l'API OpenAI")

    # Champ de texte pour saisir le terme de recherche
    search_term = st.text_input("Entrez votre terme de recherche")

    # Bouton pour lancer la recherche
    if st.button("Rechercher"):
        # Appel de la fonction de recherche avec le terme entré
        result = search_chatgpt(search_term)

        # Affichage des résultats
        if result:
            st.success("Résultat de la recherche :")
            st.write(result)
        else:
            st.warning("Aucun résultat trouvé pour ce terme de recherche.")

if __name__ == "__main__":
    main()
