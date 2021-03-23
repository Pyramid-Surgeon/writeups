# Dive Internal
Dive internal was a web challenge where the attacker needed to chain together different application behaviors to get the flag.

# Recon
For this challenge we get the source code of the web application.
```
diveinternal/
│   docker-compose.yml   
│
└───nginx/
│   │   Dockerfile
│   │   log/
|   |   nginx.conf
│   
└───private/
|   |   Dockerfile
|   └───app/
|       |   FLAG
|       |   coinapi.py
|       |   datamodel.py
|       |   nginx.conf
|       |   rollback.py
|       |   uwsgi.ini
|       |   logging.conf
|       |   main.py
|       |   requirements.txt
|       |   backup/
|       |   database/
|       └───templates/
|       |   |   index.html
|       └───logs/
|           |   KillCoinapi.log
|
└───public/
    |   Dockerfile
    └───src/
        |   app.js
        |   package.json
        └───bin/
            |   www
        └───public/
        |   |   javascript/
        |   └───images/
        |   |   |   ADA.png
        |   |   |   BTC.png
        |   |   |   LINK.png
        |   |   |   XRP.png
        |   └───stylesheets/
        |       | style.css
        └───routes/
        |   |   apis.js
        |   |   index.js
        |   |   users.js
        └───views/
            |   error.ejs
            |   index.ejs
            └───pages/
            |   |   about.ejs
            |   |   index.ejs
            |   |   subscribe.ejs
            └───partials/
                |   footer.ejs
                |   head.ejs
                |   header.ejs
```
Looking at this two things stand out;
* There is a public facing and internal facing server.
* The flag is contained on the private server.

We need to find a way to communicate with the private server and then exploit it to get the flag.

First I tried request smuggling, however afther about an hour of failed attempts I noticed the following bit of conde in main.py (The SSRF comment wasn't present in the oritional code).
```python
def LanguageNomarize(request):
    if request.headers.get('Lang') is None:
        return "en"
    else:
        regex = '^[!@#$\\/.].*/.*' # Easy~~
        language = request.headers.get('Lang')
        language = re.sub(r'%00|%0d|%0a|[!@#$^]|\.\./', '', language) # removes these characters
        if re.search(regex,language):
            return request.headers.get('Lang')
        
        try:
            # SSRF?!
            data = requests.get(request.host_url+language, headers=request.headers)
            if data.status_code == 200:
                return data.text
            else:
                return request.headers.get('Lang')
        except:
            return request.headers.get('Lang')
  ```
If we pass the regex check we have ssrf in the language header. This function is used in the /coin endpoint, this is an endpoint the public server will freely allow us to access.
```node
router.get('/coin', function(req, res, next) {
  request({
        headers: req.headers,
        uri: `http://${target}/coin`,
      }).pipe(res);
  });
  ```
  
  We now have a way to freely contact the internal server, next we need to find a way to read the flag. `rollback.py` contains the following code:
  ```python
  def RunRollbackDB(dbhash):
    try:
        if os.environ['ENV'] == 'LOCAL':
            return
        if dbhash is None:
            return "dbhash is None"
        dbhash = ''.join(e for e in dbhash if e.isalnum())
        if os.path.isfile('backup/'+dbhash):
            with open('FLAG', 'r') as f:
                flag = f.read()
                return flag
        else:
            return "Where is file?"
  ```
  If it gets a database hash that exists in the backup folder it will give us the flag. Now this function is called in the integrity check function:
  ```python
  def IntegrityCheck(self,key, dbHash): 

        if self.integrityKey == key:
            pass
        else:
            return json.dumps(status['key'])
        if self.dbHash != dbHash:
            flag = RunRollbackDB(dbHash)
            logger.debug('DB File changed!!'+dbHash)
            file = open(os.environ['DBFILE'],'rb').read()
            self.dbHash = hashlib.md5(file).hexdigest()
            self.integrityKey = hashlib.sha512((self.dbHash).encode('ascii')).hexdigest()
            return flag
        return "DB is safe!"
 ```
It takes a key and a database hash, if the key is valid it will check if the databasehash matches, if this is not the case it will call our `RunRollbackDB` function.
 
We now have the following objective:
 * Get the database key
 * Get file write in /backup.
 
To get the database key we need a valid dbhash, the key is a sha512sum of the dbhash. Lucklily, the `/IntegrityStatus` endpoint gives us the database hash.
 
To get write in /backup we can use the `/download` endpoint. This will check the signature and, if it matches, download the file.
It took me a while to figure out how to forge the signature, eventually I noticed the signature key was hardcoded at the top.
```python
privateKey = b'let\'sbitcorinparty'
```
Using this we can calculate the database key and write an arbitrary file in /backup. We can then call the `/rollback` endpoint with both our key and our signature in order to read the flag.
