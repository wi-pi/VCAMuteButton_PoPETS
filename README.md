# Are You Really Muted?: A Privacy Analysis of Mute Buttons in Video Conferencing Apps

This repository contains the source code and sample data for the PETS'22 paper by Yucheng Yang, Jack West, George K. Thiruvathukal, Neil Klingensmith, and Kassen Fawaz.


### Dependencies

There are two components to this repository.
This repository contains the C code examples for Linux data gathering and python scripts to gather, examine, and plot data.
Tools needed to run the code:

    - GCC
    - Python3
    - make 
    - portaudio19-dev


## Virtual Environment Setup

The python scripts have a few dependencies.
We recomend using a virtal environment when installing the packages.
However, if one does not want to use a virtual environment, install using the command `pip install -r ./requirements.txt`

For those interested in using a virtual environment, the instructions are as follows:
    
```bash 
#First create the environment in the root directory. 
> python3 -m venv Mute_Button

#Then run this command
> source Mute_Button/bin/activate
#The above command will put your shell into the context of the python virtual environment

#Then, once in the environment, your terminal should have the name of the environment leading the terminal command.
#Now you may install the python packages. 
(Mute_Button) > pip3 install -r ./requirements.txt

```

The above commands are designed for linux.
Windows has a slightly different process, to access instructions for the same process on Windows go [here](https://docs.python.org/3/tutorial/venv.html).

The virtual environment will create a `Mute_Button` folder which will be about `2 GBs`.


## Componets
Here is a brief description of the subdirectories in this repository.

- `UserStudy`: full user study analysis script and user study results of all valid participants, coded answers by two researchers, and user study questionnaire details.
- `BgActivityClassifier`: python scripts for training our background activity classifiers.
- `dataset`: extracted sample data from Webex outgoing traffic.
- `scripts`: traffic interception scripts used for capturing telemetric packets from Webex outgoing traffic.


### Authors 

[Yucheng Yang](https://wiscprivacy.com/member/member_yucheng/) - [Github](https://github.com/Easycomer) - [yang552@wisc.edu](yang552@wisc.edu)

[Jack West](https://jacksonwaynewest.com/) - [Github](https://github.com/jweezy24) - [jwest1@luc.edu](jwest1@luc.edu)

