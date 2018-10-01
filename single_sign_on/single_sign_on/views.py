from django.views import View
from django.shortcuts import redirect, render
from django.contrib.auth.mixins import LoginRequiredMixin


class HomeView(LoginRequiredMixin, View):
	""" 
		home view can access only logedin user
	"""
	def get(self, request):
		context = {}
		return render(request, 'home.html' , context)