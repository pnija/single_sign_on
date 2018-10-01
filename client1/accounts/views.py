from django.views import View
from django.shortcuts import redirect, render
from django.conf import settings
import jwt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from .models import AccessInfo
from django.http import JsonResponse


class LoginView(View):
	"""
		Redirect all login request to SP login page
		loged in user redirect to LOGIN_REDIRECT url
	"""
	def get(self, request):
		if request.user.is_authenticated:
			return redirect(settings.LOGIN_REDIRECT)

		redirect_url = request.scheme +'://'+request.get_host()+'/accounts/login-info/'
		token = jwt.encode({'redirect_url': redirect_url}, settings.JWT_SECRET, algorithm='HS256')

		return redirect('http://example.com:8000/accounts/check-login/%s' %token.decode())


class LoginInfoView(View):
	"""
		saving loged in user info in db and loged in that user in client site
	"""

	def get(self, request, *args, **kwargs):
		token = kwargs['token']
		del request.user
		user_info = jwt.decode(token.encode(), settings.JWT_SECRET, algorithms=['HS256'])
		user, create = User.objects.get_or_create(id=user_info['id'], username = user_info['username'])
		login(request, user)
		AccessInfo.objects.create(session_id=request.session.session_key, access_token=user_info['access_token'])

		return redirect(settings.LOGIN_REDIRECT)


class LogoutView(View):
	"""
		this view redirect logout request to service provider
	"""
	def get(self, request, *args, **kwargs):

		redirect_url = request.scheme +'://'+request.get_host()+settings.LOGOUT_REDIRECT
		access_token = AccessInfo.objects.get(session_id=request.session.session_key).access_token

		data = {
			'redirect_url': redirect_url,
			'access_token': access_token
		}

		token = jwt.encode(data, settings.JWT_SECRET, algorithm='HS256')

		return redirect('http://example.com:8000/accounts/process-logout/%s' %token.decode())

class ProcessLogoutView(View):
	"""
		this view loged out current user by request from access provider
	"""
	def get(self, request, *args, **kwargs):

		token = kwargs['token']

		try:
			access_token = jwt.decode(token.encode(), settings.JWT_SECRET, algorithms=['HS256'])['access_token']
			session = AccessInfo.objects.get(access_token=access_token).session
			session.delete()
			
			return JsonResponse({'status': 'success'})
		except:
			return JsonResponse({'status': 'invalid'})


class LogoutSuccessView(View):
	def get(self, request, *args, **kwargs):
		return render(request, 'loged_out.html' , {})

