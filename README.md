# Django-Bad-Practices

## Django Bad Practices: Attributes in Deny List

### Abstract
The application uses a deny list to control which attributes are exposed by a form. Developers can forget to update the deny list when adding new attributes and may accidentally expose sensitive fields to attackers.
### Explanation
The application uses an exclude deny list. This is hard to maintain and error prone. If developers add new fields to the form or Model that backs up the form and forget to update the exclude filter, they may be exposing sensitive fields to attackers. Attackers will be able to submit and bind malicious data to any non-excluded field.

Example 1: The following form exposes some User attributes but checks a deny list for the user id:

```
from myapp.models import User
...
class UserForm(ModelForm):
  class Meta:
    model = User
    exclude = ['id']
...
```

If User model was updated with a new role attribute and the associated UserForm was not updated, the role attribute would be exposed in the form.

## Django Bad Practices: Cookie Stored Sessions

### Abstract
Cookie-based sessions are not invalidated when a user logs out. If an attacker were to find, steal, or intercept a user's cookie they could impersonate the user even if that user had logged out.
### Explanation
Storing session data in Cookies presents several problems:

1. Cookie-based sessions are not invalidated when a user logs out. If an attacker were to find, steal, or intercept a user's cookie they could impersonate the user even if that user had logged out.

2. Session cookies are signed to avoid tampering and guarantee the authenticity of the data, but it will not prevent replay attacks.

3. The session data will be stored using Django's tools for cryptographic signing and the SECRET_KEY setting. If the SECRET_KEY is leaked, an attacker cannot only falsify session data, but if application uses Pickle to serialize session data into cookies, an attacker will be able to craft malicious pickled data that will execute arbitrary code upon deserialization.

4. The session data is signed but not encrypted. This means that attackers will be able to read the session data but not modify it.

5. The cookie size and serialization process can pose a performace problem depending on site load.



## Django Bad Practices: Overly Broad Host Header Verification

### Abstract
Not validating the Host header can allow an attacker to send a fake Host value that can be used for Cross-Site Request Forgery, cache poisoning attacks, and poisoning links in emails.
### Explanation
The Django applications settings specifies "*" as an entry in the ALLOWED_HOSTS setting. This setting is used by django.http.HttpRequest.get_host() to validate the Host header. A value of "*" will allow any host in the Host header. An attacker may use this in cache poisoning attacks or for poisoning links in emails.

Example 1: An application offers a reset password feature where users can submit some kind of unique value to identify themselves (eg: email address) and then a password reset email will be sent with a link to a page to set up a new password. The link sent to the user can be constructed using the Host value to reference the site that serves the reset password feature in order to avoid hardcoded URLs. For example:

```
...
def reset_password(request):
  url = "http://%s/new_password/?token=%s" % (request.get_host(), generate_token())
  send_email(reset_link=url)
  redirect("home")
...
```

An attacker may try to reset a victim's password by submitting the victim's email and a fake Host header value pointing to a server he controls. The victim will receive an email with a link to the reset password system and if he decides to visit the link, she will be visiting the attacker-controlled site which will serve a fake form to collect the victim's credentials.

## Django Bad Practices: Pickle Serialized Sessions

### Abstract
Pickle-serialized sessions can lead to remote code execution if attackers can control session data.
### Explanation
If cookie-based sessions are used and SECRET_KEY is leaked, an attacker will be able to store arbitrary data in the session cookie which will be deserialized in the server leading to arbitrary code execution.

If cookie-based sessions are used, take extra care to make sure that the secret key is always kept completely secret, for any system which might be remotely accessible.

Example 1: The following view method allows an attacker to steal the SECRET_KEY if it is hardcoded in settings.py configuration file:

```
...
def some_view_method(request):
  url = request.GET['url']
  if "http://" in url:
    content = urllib.urlopen(url)
    return HttpResponse(content)
  ...
  ```
Example 1 method checks that the url parameter is a valid URL by checking that "http://" is present in the URL. A malicious attacker may send the following URL to leak the settings.py configuration file that may contain the SECRET_KEY:

```
file://proc/self/cwd/app/settings.py#http://
```

Note: "/proc/self/cwd" in UNIX systems points to the process working directory. This allow attackers to reference files without knowing the exact location.
