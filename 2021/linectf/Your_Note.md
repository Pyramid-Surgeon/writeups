# Your note
Your note was a client web challenge, the flag is a note on the admins account. The intended path was to trick the admin onto your website, 
send arbitrary search queries and detect if the result was successfull by checking for downloads as described in [xsleaks](https://xsleaks.dev/docs/attacks/navigations/).

The setup of this challenge reminded me a lot of the wallet challenge in the [wectf](https://github.com/wectf/2020p). However there were three issue's preventing this
technique from working. The final one we unfortunatly never solved.

# Picky admin
Fortunatly we get the admin script `crawler.js`, here we encounter our first issue:
```js
const base_url = 'http://' + host;
if (url && url.startsWith(base_url + '/') &&
  proof && prefix && verify(proof, prefix)) {
  // visit our link
  }
```
The bot will only visit the challenge website, however this turned out to be the easiest obstacle to bypass, it was also the only step in this kill chain that was intended.

The login page for the website contains a redirect. Looking at the code there seems to be a difference between it and the crawler script.
```python
@app.route('/login', methods=['GET', 'POST'])                                                                                              
def login():                                                                                                                               
    url = request.args.get('redirect')                                                                                                     
    if url:                                                                                                                                
        url = app.config.get('BASE_URL') + url                                                                                             
        if current_user.is_authenticated:                                                                                                  
            return redirect(url)
```

The redirect doesn't append the backslash. If this was using DNS we could turn this into an open redirect with the use of subdomains. A redirect payload of `.attacker.com`
Would result in the user being redirected to `BASE_URL.attacker.com`. However in this case the website wasn't using domains, instead we only had the IP. Given a specific
IP there is a way to still use this method. For example if the IP is `123.123.123.1` you could send a payload of `5/index.html` however this requires you to own `123.123.123.15`.
Turns out, there is a way easier sollution. 

According to [RFC 3986](https://tools.ietf.org/html/rfc3986) user information can be stored before the @ sign in an URL. However;
```
Use of the format "user:password" in the userinfo field is
   deprecated.  Applications should not render as clear text any data
   after the first colon (":") character found within a userinfo
   subcomponent unless the data after the colon is the empty string
   (indicating no password).
```
In modern browsers this means a popup will be created asking the user if they want to visit this site. There is however a subtle difference in how browsers handel this.
If the website doesn't use http authentication or requires http authentication but will accept any username:password combination the default value of this popup will be "no" (and it will include a scary anti scamming message).
However if the website requires a specific username the default value will be "yes" (tested on firefox).

Using this we can setup a server requiring http authentication with the website's IP as username. The payload becomes `@attacker.com` which then redirects the admin to an attacker controlled site.

# Bypass CORB
This was quite tricky, browsers allow websites to exchange resources, however unless otherwise specified by the website hosting the resource this is pretty much exclusive to javascript. 
In the wallet challenge you could pollute the main page into returning a js variable. This was the idea here, the website had a download function allowing you to fetch a json payload of all the notes.
However for this to be parsed as JS we need it inside a variable which we can in turn call.

We spent a long time on this, eventually we found this very neat trick by [the spanner](http://www.thespanner.co.uk/2011/05/30/json-hijacking/). You can specify the encoding
when calling external resources. Because UTF-8 and UTF-7 appear to differ quite drasticly we can abuse this in the following way:
### External site (UTF-8)
```
[{"title": "flag", "content": "a+ACI-+AH0-+AF0-+ADs-+ACA-a+ACA-+AD0-+ACA-+AFs-+AHs-+ACI-delta+ACI-:+ACI-A", "id": "08de324f-a5e7-4f23-aab5-52ab34cfdb6a"}, {"title": "flag", "content": "FLAG{hi}", "id": "bb4dc1c6-1b43-4a35-a591-46dc3699e0b7"}]
```
### Our site (UTF-7)
```
<script type="text/javascript" charset="UTF-7" src="target.com"></script>
[{"title": "flag", "content": "a"}]; a = [{"delta":"A", "id": "08de324f-a5e7-4f23-aab5-52ab34cfdb6a"}, {"title": "flag", "content": "FLAG{hi}", "id": "bb4dc1c6-1b43-4a35-a591-46dc3699e0b7"}]
```
We now have an array "a" with all the notes in it which we can then send to a collection server and read the flag.

# CSRF
For the previous trick to work we need to be able to create a note with the content or title as `a+ACI-+AH0-+AF0-+ADs-+ACA-a+ACA-+AD0-+ACA-+AFs-+AHs-+ACI-delta+ACI-:+ACI-A`. With most web challenges this would be trivial but,
presumably to prevent users from creating obsene notes or breaking the challenge, this challenge had CSRF tokens on every major endpoint, including the one for creating notes.

We spent a considerable amount of time trying to find an exploit in flask-wtf's CSRF module. At this point we were quite sure we weren't doing the challenge the intended way however with the amount of effort already invested
we opted to try to make it work as opposed to starting from scratch.
