from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from project_user import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login

# Create your views here.

def signup(request):
  context={}
  if request.method=="GET":
    return render(request, 'app_user/index.html', context)
  elif request.method=="POST":
    username = request.POST.get('Username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    if email is not None:
      user = User.objects.create_user(username=username, email=email)
      user.set_password(password)
      user.is_active = False
      user.save()
      domain = request.get_host()
      # current_site = get_current_site(request).domain
      message = render_to_string('app_user/active_email.html', {
                    'user': user,
                    'domain': domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
      email = EmailMessage(
                'Activate your account',  # subject
                message, # body
                settings.EMAIL_HOST, # from
                to=[email],  # to
            )
      email.send()
      return HttpResponse('sign-up')
    else:
      user = authenticate(username=username, password=password)
      if user is not None:
        login(request, user)
        u = 'Hello '+str(request.user)
        return HttpResponse(u)
      else:
        messages.error(request, "Username and password did not matched")
        return render(request, 'app_user/index.html', context)
      # return HttpResponse('Login')


def activate(request, uidb64, token):
  try:
      uid = int(urlsafe_base64_decode(uidb64))
      user = User.objects.get(id=uid)
  except(TypeError, ValueError, OverflowError, User.DoesNotExist):
      user = None
  if user is not None and default_token_generator.check_token(user, token):
      user.is_active = True
      user.save()
      print(default_token_generator.check_token(user, token))
      return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
  else:
      return HttpResponse('Activation link is invalid!')

  
  # print(request.get_host())
  # return render(request, 'app_user/index.html', context)
  # user = authenticate(username=username, password=password)
      


# from django.contrib.auth.models import User
# from django.contrib.auth.tokens import default_token_generator
# from django.core.mail import EmailMessage
# from django.template.loader import render_to_string
# from django.utils.encoding import force_bytes
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.contrib import messages
# from django.contrib.auth import authenticate, login