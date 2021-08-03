# fuzzer-dc2513
fuzzer-dc2513 created by GitHub Classroom

This program is meant to test the vulnerabilities of any given url or website. 
Some prerequisites for this program are as follows:
  Mechanical Soup (https://github.com/MechanicalSoup/MechanicalSoup)

To run this program, you must go to the directory where 'fuzz.py' installed and run a command line.
From the command line, you can run the program by typing 'fuzz.py (python fuzz.py on Mac OS or Linux) followed
by -h or --help to see a list of commands you can use on the program.


The following command is what you will need to run in order to run the fuzzer with the gruyere: 

python fuzz.py test [Website with instanceID here] 
--custom-auth=gruyere --common-words=commonPages.txt --vectors=vectors.txt --sensitive=sensitive.txt 
--random=false --slow=1000

DVWA: 

python fuzz.py test http://127.0.0.1/dvwa --custom-auth=dvwa --common-words=commonPages.txt --vectors=vectors.txt --sensitive=sensitive.txt --random=false --slow=1000

python fuzz.py test http://www.google.com --common-words=commonPages.txt --vectors=vectors.txt --sensitive=sensitive.txt --random=false --slow=1000