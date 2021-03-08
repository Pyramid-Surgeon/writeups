# Bashlexy

Bashlexy was a restricted shell challenge using the bashlex command parser for python.

Taking a look at the source code it validates our command and, if the check succeeds, runs it. Upon closer inspection of the validation function,
```python
def validate(ast):
    queue = [ast]
    while queue:
        node = queue.pop(0)
        if node.kind == 'command':
            first_child = node.parts[0]
            if first_child.kind == 'word':
                if first_child.parts:
                    print(f'Forbidden top level command')
                    return False
                elif first_child.word.startswith(('.', '/')):
                    print('Path components are forbidden')
                    return False
                elif first_child.word.isalpha() and \
                        first_child.word not in ALLOWED_COMMANDS:
                    print('Forbidden command')
                    return False
        elif node.kind == 'commandsubstitution':
            print('Command substitution is forbidden')
            return False
        elif node.kind == 'word':
            if [c for c in ['*', '?', '['] if c in node.word]:
                print('Wildcards are forbidden')
                return False
            elif 'flag' in node.word:
                print('flag is forbidden')
                return False
```
the folowing rules stand out:
  * The string "flag" can't be in the command
  * The command has to be alphabetic for it to be checked against the ALLOWED_COMMANDS (first_child.word.isalpha())

Command paramaters aren't checked. Because of legacy reasons most linux installations come with two python binaries, one of them running some version of python 2
and the other one running some version of python 3. These binaries are specified as python2 and python3 respectivly, because these contain a number they don't 
pass the .isalpha check and as such arn't checked. 

Using this we can execute arbitary python code and get the flag with a payload such as 
`python3 -c 'import os; os.system("cat /home/bashlex/fla" + "g.txt")'`
