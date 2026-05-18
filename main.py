from ollama import chat

def main():


    response = chat(
        model='llama3.1:8b',
        messages=[{'role': 'user', 'content': 'Cuál es la capital de Turquía?'}],
)
    print(response.message.content)
    
    print("Hello from alert-correlation!")


if __name__ == "__main__":
    main()
