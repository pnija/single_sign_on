from django.shortcuts import render
from django.views import View
from django.http import HttpResponse
from django.shortcuts import redirect, reverse
from django.contrib.auth.views import LoginView
import jwt
from django.conf import settings
from .models import AccessInfo, AccessInfoSite
import uuid
from urllib.parse import urlparse
from django.http import Http404
from urllib.request import urlopen
from django.contrib.auth import logout


class CustomLoginView(LoginView):

	def get(self, request):
		if request.user.is_authenticated:
			return redirect(settings.LOGIN_REDIRECT)
		
		try:
			CustomLoginView.token = self.request.session['token']
			del self.request.session['token']

		except:
			CustomLoginView.token = None

		return super().get(request)

	def get_success_url(self):

		#holding information of loged in info in db
		access_token = str(uuid.uuid4())
		access_info = AccessInfo.objects.create(session_id=self.request.session.session_key, access_token=access_token)

		try:

			token = CustomLoginView.token

			redirect_url = jwt.decode(token.encode(), settings.JWT_SECRET, algorithms=['HS256'])['redirect_url']
		
			user_info = {
				'id': self.request.user.id, 
				'username': self.request.user.username,
				'access_token' : access_token
			}

			user_info_token = jwt.encode(user_info, settings.JWT_SECRET, algorithm='HS256')
			redirect_url = redirect_url+ user_info_token.decode()

			#holding loged in site info in db
			parsed_url = urlparse(redirect_url)
			website_url = parsed_url.scheme + "://" + parsed_url.netloc
			AccessInfoSite.objects.create(access_info=access_info, website_url=website_url)

		except:
			redirect_url = settings.LOGIN_REDIRECT



		return redirect_url


class CheckLogin(View):

	def get(self, request, *args, **kwargs):
		
		try:
			request.session['token'] = self.kwargs['token']
		except:
			pass

		redirect_url = request.scheme +'://'+request.get_host()+'/accounts/check-login-status/'

		context = {
			'redirect_url' : redirect_url
		}
		return render(request, 'login_check.html', context)


class CheckLoginStatus(View):

	def get(self, request):
		if request.user.is_authenticated:

			try:
				token = request.session['token']

				#holding information of loged in info in db
				access_info = AccessInfo.objects.get(session_id=self.request.session.session_key)
				
				redirect_url = jwt.decode(token.encode(), settings.JWT_SECRET, algorithms=['HS256'])['redirect_url']
			
				user_info = {
					'id': self.request.user.id, 
					'username': self.request.user.username,
					'access_token' : access_info.access_token
				}

				user_info_token = jwt.encode(user_info, settings.JWT_SECRET, algorithm='HS256')
				redirect_url = redirect_url+ user_info_token.decode()

				#holding loged in site info in db
				parsed_url = urlparse(redirect_url)
				website_url = parsed_url.scheme + "://" + parsed_url.netloc
				AccessInfoSite.objects.create(access_info=access_info, website_url=website_url)

			except:
				redirect_url = settings.LOGIN_REDIRECT

			return redirect(redirect_url)

		else:
			return redirect(reverse('login'))


class ProcessLogoutView(View):
	def get(self, request, *args, **kwargs):
		
		try:
			#accessing token info in session
			request.session['token'] = self.kwargs['token']

			return redirect(reverse('logout'))
		except:

			return Http404('Page not Found')


class LogoutView(View):
	def get(self, request, *args, **kwargs):

		try:
			token = request.session['token']
			data = jwt.decode(token.encode(), settings.JWT_SECRET, algorithms=['HS256'])
			logedin_domains = AccessInfoSite.objects.filter(
				access_info__access_token=data['access_token']).values_list('website_url', flat=True)

			for domain in logedin_domains:
				access_domain = domain+'/accounts/process-logout/%s' %token

				try:
					urlopen(access_domain)
				except:
					pass

			redirect_url = data['redirect_url']

		except:
			access_token = AccessInfo.objects.get(session=request.session.session_key).access_token
			logedin_domains = AccessInfoSite.objects.filter(
				access_info__access_token=access_token).values_list('website_url', flat=True)
			token = jwt.encode({'access_token':access_token}, settings.JWT_SECRET, algorithm='HS256')

			for domain in logedin_domains:
				access_domain = domain+'/accounts/process-logout/%s' %token.decode()

				try:
					urlopen(access_domain)
				except:
					pass

			redirect_url = settings.LOGOUT_REDIRECT

		logout(request)

		return redirect(redirect_url)


class LogoutSuccessView(View):
	def get(self, request, *args, **kwargs):
		return render(request, 'loged_out.html' , {})
