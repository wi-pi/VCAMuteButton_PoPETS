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


## Docker Setup

We also offer docker as an alternative method for executing our code base.
Those who wish to use the docker be warned that the image will be `8Gb`.

You will need to download Dynamorio, I recommend [this version](https://github.com/jweezy24/dynamorio). The reason why we do not recommend the current release is that there seems to be version specific bug that causes a crash within the software. We were able to find the bug and offer a temporary solution. This seems to be related to docker as when tested outside of docker the release version works as intended. We currently have an [open github issue](https://github.com/DynamoRIO/dynamorio/issues/5554) addressing the matter.

### Steps
Below  we will walk a user through how to install the docker image on their machine.
We assume that the user has docker installed.

1. Clone DynamoRIO in the root of this reposoitory(see second paragraph of this section for version recomendations).
2. `docker build -t vca .` This step builds the docker image using the build script our repository's home directory. The build requires at least `8Gb` of free space. This step compiles dynamorio and installs all the python dependencies. Also, the compiling of dynamorio will take all cores. If that is an issuem, you can change the `make -j` setting in the docker script to what you would like.
3. `docker run -itd vca ` This command creates a container for the image we have just created after running the first command.
4. `docker exec -it <Name of container> /bin/bash ` This command will allow the user to enter the container and execute the code. You can get the name of a currently active container by running, `docker ps `. Upon entering the command, you will now be able to execute all code with little issue. 
 
 

## Componets
Here is a brief description of the subdirectories in this repository.

- `UserStudy`: full user study analysis script and user study results of all valid participants, coded answers by two researchers, and user study questionnaire details.
- `BgActivityClassifier`: python scripts for training our background activity classifiers.
- `dataset`: extracted sample data from Webex outgoing traffic.
- `scripts`: traffic interception scripts used for capturing telemetric packets from Webex outgoing traffic.


### Authors 

[Yucheng Yang](https://wiscprivacy.com/member/member_yucheng/) - [Github](https://github.com/Easycomer) - [yang552@wisc.edu](yang552@wisc.edu)

[Jack West](https://jacksonwaynewest.com/) - [Github](https://github.com/jweezy24) - [jwest1@luc.edu](jwest1@luc.edu)

