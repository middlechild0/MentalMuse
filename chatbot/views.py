from django.shortcuts import render, redirect
from django.http import JsonResponse
import google.generativeai as genai
from django.contrib import auth
from django.contrib.auth.models import User
from .models import Chat
from django.utils import timezone
from cryptography.fernet import Fernet
import os
import logging

# Configure the Gemini API
API_KEY = os.getenv('GEMINI_API_KEY')

# Create the model configuration
generation_config = {
    "temperature": 0,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
    system_instruction="You are an expert at giving therapy...",
)

# Load or generate a key for encryption (ensure this key is consistent)
KEY_FILE = "secret.key"

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

key = load_key()
cipher = Fernet(key)

# Function to encrypt the message
def encrypt_message(message):
    try:
        encrypted_message = cipher.encrypt(message.encode('utf-8')).decode('utf-8')
        return encrypted_message
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return None

# Function to decrypt the message
def decrypt_message(encrypted_message):
    try:
        decrypted_message = cipher.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
        return decrypted_message
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None

# Function to ask Gemini and get a response
def ask_gemini(message):
    try:
        chat_session = model.start_chat()
        response = chat_session.send_message(message)
        return response.text
    except Exception as e:
        logging.error(f"Error while getting response from Gemini: {e}")
        return "Sorry, I couldn't get a response at the moment."

def chatbot(request):
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect to login if not authenticated
    
    chats = Chat.objects.filter(user=request.user).order_by('created_at')
    
    if request.method == 'POST':
        message = request.POST.get('message', '')
        response = ask_gemini(message)

        # Encrypt the message and response
        encrypted_message = encrypt_message(message)
        encrypted_response = encrypt_message(response)
        
        # Save the chat to the database
        chat = Chat(user=request.user, message=encrypted_message, response=encrypted_response, created_at=timezone.now())
        chat.save()

    # Decrypt the chats for display
    decrypted_chats = []
    for chat in chats:
        decrypted_message = decrypt_message(chat.message)
        decrypted_response = decrypt_message(chat.response)
        if decrypted_message and decrypted_response:
            decrypted_chats.append({'message': decrypted_message, 'response': decrypted_response})
    
    # Render the chatbot template with the chats
    return render(request, 'chatbot.html', {'chats': decrypted_chats})

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(request, username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('chatbot')
        else:
            error_message = "Invalid credentials"
            return render(request, 'login.html', {'error_message': error_message})
    return render(request, 'login.html')

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        if password1 == password2:
            try:
                user = User.objects.create_user(username=username, email=email, password=password1)
                user.save() 
                auth.login(request, user)
                return redirect('chatbot')  
            except Exception as e:
                error_message = str(e)
                return render(request, 'register.html', {'error_message': error_message})
        else:
            error_message = "Passwords do not match"
            return render(request, 'register.html', {'error_message': error_message})
    return render(request, 'register.html')

def logout(request):
    if request.method == 'POST':
        auth.logout(request)
        return redirect('login')  # Redirect to login after logout
    return redirect('login')
