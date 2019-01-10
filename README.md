# Needham-Schroeder Attack

The Python files were written in Python 3.7.

## Initial Setup

pycryptodome is the only dependency required, as it contains the Crypto packages. To install, enter the following command:
```
$ pip install pycryptodome
```

To setup the RSA keys of Alice, Bob, and Mallory, run the setup.py script:
```
$ python setup.py
```

## Required Files
* setup.py
* alice/alice.py
* alice/alice-fix.py
* bob/bob.py
* bob/bob-fix.py
* mallory/mallory.py
* mallory/bad_file.txt
* pks/pks.py
* helpers/__init__.py
* helpers/ns.py
* helpers/rsa.py
* helpers/aes.py

## Running the Protocol
To run the Needham-Schroeder protocol between Alice and Bob, first open a command-line shell and run bob.py with the following command:
```
$ python3 bob.py
```

To execute the protocol, go to the alice folder and open another shell window to execute alice.py. An example of a command would be:
```
$ python3 alice.py -s bob my_file.txt
```

After running, a folder named 'alice' with the inputted file should appear under the bob folder.

## Running the Attack
To run the attack, mallory.py and bob.py must be first running in their separate shells:
```
$ python3 bob.py
```
```
$ python3 mallory.py
```

To execute the attack, go to the alice folder and open another shell window to execute alice.py. An example of a command would be:
```
$ python3 alice.py -s mallory my_file.txt
```

After running, a file named 'bad_file.txt' would be appear in the alice folder under the bob folder.

## Running the Fix
To run the fixed protocol, mallory.py and bob-fix.py must be first running in their separate shells:
```
$ python3 bob-fix.py
```
```
$ python3 mallory.py
```

To execute the protocol, go to the alice folder and open another shell window to execute alice-fix.py. An example of a command would be:
```
$ python3 alice-fix.py -s mallory my_file.txt
```

If bob was given as a server argument to alice-fix.py, the result would be the exact same as running the normal protocol.

## Sources
* [Socket Programming in Python (Guide)](https://realpython.com/python-sockets/)
