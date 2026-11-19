import os
from dotenv import load_dotenv
from groq import Groq

# Load the .env file
load_dotenv()

# Read the API key
client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

def ask_ai(question):

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AI assistant for a Life Insurance Verification Portal. "
                    "Answer only questions related to life insurance, policies, claims, "
                    "premium payments, KYC, and policy verification."
                )
            },
            {
                "role": "user",
                "content": question
            }
        ]
    )

    return response.choices[0].message.content