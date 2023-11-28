from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView,UpdateView,FormView
from .models import Task
from django.urls import reverse_lazy
from django.db import connection
from django.db.models import Q
from django.contrib.auth import login
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth import  login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User




# Solution to Flaw #A01:2021-Broken Access Control
# This makes sure  that only authenticated users can access certain views.
# from django.contrib.auth.mixins import LoginRequiredMixin



#Flaw 4 A02:2021-Cryptographic Failures
from django.contrib.auth.backends import ModelBackend

class CustomRegistrationForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput())  
    
    def save(self):
        user_model = get_user_model()
        user = user_model(
            username=self.cleaned_data['username'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password'] 
        )
        user.save()
        return user
    

#Flaw 4 A02:2021-Cryptographic Failures
class PlainTextBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = User.objects.get(username=username)
            if user.password == password:
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
        
#Flaw 4 A02:2021-Cryptographic Failures
class RegisterPage(FormView):
    template_name = 'base/register.html'
    form_class = CustomRegistrationForm
    redirect_authenticated_user = True
    success_url = reverse_lazy('tasks')

    def form_valid(self, form):
        user = form.save()

        auth_backend = PlainTextBackend()
        authenticated_user = auth_backend.authenticate(
            self.request,
            username=form.cleaned_data['username'],
            password=form.cleaned_data['password']
        )

        if authenticated_user:
            login(self.request, authenticated_user)
        else:
            print("Authentication failed")

        return super().form_valid(form)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.pop('request', None)
        return kwargs
    
#Flaw 4 A02:2021-Cryptographic Failures
#Solution
#class RegisterView(FormView):
#    template_name = 'base/register.html'
#    form_class = UserCreationForm
#    redirect_authenticated_user = True
#    success_url = reverse_lazy('tasks')

#    def form_valid(self, form):
#        user = form.save()
#        if user is not None:
#            login(self.request, user)
#        return super().form_valid(form)

#    def get(self, *args, **kwargs):
#        if self.request.user.is_authenticated:
#            return redirect('tasks')
#        return super().get(*args, **kwargs)



class ClientLoginView(FormView):
    template_name = 'base/login.html'
    form_class = AuthenticationForm
    success_url = reverse_lazy('tasks')

    def authenticate(self, username=None, password=None):
        try:
            user = PlainTextBackend().authenticate(
                self.request,
                username=username,
                password=password
            )
            return user
        except Exception as e:
            print(f"Authentication error: {e}")
            return None

    def form_valid(self, form):
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        auth_user = self.authenticate(username=username, password=password)

        if auth_user:
            login(self.request, auth_user)
            return super().form_valid(form)
        else:
            print("Authentication failed")
            return self.form_invalid(form)
        

#Flaw 2
#A01:2021-Broken Access Control
class TaskList(ListView):
# Solution
#class TaskList(LoginRequiredMixin,ListView):
    model = Task
    context_object_name = 'tasks'
    template_name = 'task_list.html'  

    def get_queryset(self):
        query = self.request.GET.get('q')
        if query:
            return Task.objects.filter(Q(title__icontains=query) | Q(description__icontains=query))
        else:
            return Task.objects.all()
#Flaw 2
#A01:2021-Broken Access Control 
    def get_context_data(self,**kwargs):
        context = super().get_context_data(**kwargs)
        context['tasks'] = Task.objects.all()    
        # Solution
        # context ['tasks']= context ['tasks'].filter(user=self.request.user)
        return context


#Flaw 2
#A01:2021-Broken Access Control
class TaskDetail (DetailView):  
# Solution
# class TaskDetail(LoginRequiredMixin,DetailView):
    model=Task
    context_object_name='task'

#Flaw 2
#A01:2021-Broken Access Control
class TaskCreate(CreateView):
# Solution
# class TaskCreate(LoginRequiredMixin,CreateView):
    model = Task
    fields = '__all__'
    success_url = reverse_lazy('tasks')
    template_name = 'base/task_form.html'

#Flaw 1
#A03:2021-Injection
# Solution is to remove this function
    def form_valid(self, form):
        title = form.cleaned_data['title']
        description = form.cleaned_data['description']

        raw_query = """
            INSERT INTO base_task (title, description, complete, created)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
        """
        with connection.cursor() as cursor:
            cursor.execute(raw_query, [title, description, False])
            
        return HttpResponseRedirect(self.success_url)

#Flaw 2
#A01:2021-Broken Access Control
class TaskUpdate(UpdateView):
# class TaskUpdate(LoginRequiredMixin,UpdateView):
    model = Task
    fields = '__all__'
    success_url = reverse_lazy('tasks')