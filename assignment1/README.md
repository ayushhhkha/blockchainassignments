# Assignment 1

In order to run this the best way is to do it in a python virtual environment. Assuming this is using WSL:

`python3 -m venv .venv`
`source .venv/bin/activate`

Ensure all dependencies are downloaded using the following:

`python -m pip install git+https://github.com/Tribler/py-ipv8.git`

To obtain the hash and nonce run the proof of work python file via the following command:

`python pow.py`

Then to run the client:

`python ipv8client.py`
