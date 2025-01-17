from django.urls import path
from . import views

urlpatterns = [
    path('', views.chatbot, name='chatbot'),     
    path('chatbot/', views.chatbot, name='chatbot'),  
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('register/', views.register, name='register'),
]
