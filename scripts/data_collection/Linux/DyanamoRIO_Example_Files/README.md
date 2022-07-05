# DynamoRIO Information

In this folder we show an example as to how we traced functions using [DynamoRIO](https://dynamorio.org/) in Linux.

**THIS CODE WILL ONLY WORK ON LINUX OR THE SUPPLIED DOCKER IMAGE**

## Installation of DynamoRIO

You will first need to install [DynamoRIO](https://dynamorio.org/), the process is different per operating system.
Instructions can be found on their website.
Once complete, you need to set an environment variable title `DYNAMO` to the install location `export DYNAMO=<install path>`.


## How DynamoRIO Works

Our `dr_showcase.c` is where our main function will live.
In the folder `simple_c_example` we wrote a very simple shared library called `encryption_lib.c`.
It creates a shared library file called `ec_lib.so`.
The main file is then dynamically links to the library to have access to the `encrypt_string` function.

What DynamoRIO does is hook itself into the dynamic calls to the `encrypt_string` function.
Once hooked, we can retrieve the arguments given to the function, change the arguments, or replace them entirely.

We chose to use DynamoRIO for our analysis because microphone APIs are commonly dynamically linked during runtime and several native applications on linux can be anaylized using the tool.

## Compiling and Running the code

First, the user must compile the code in the `simple_c_example` folder.
Once the user is in the folder, they type `make`.
When compilation finishes, the user then should go up one folder and type `make` again.
This will compile the injection code.
Finally, the user should type `make run` to run the main code as well as inject our DynamoRIO code.
The code will then capture the buffer and write the exact bytes to the `test.log` file.
Upon inspection, one will see the arguments embedded within the bytes.

## Overview of Steps
    1. `cd into simple_c_example/`
    2. `make`
    3. `cd ..`
    4. `make`
    5. `make run` (if you are in the docker image, you run `make docker`)


## Objdump Parser

The objdump parser is a python script that parses output from objdump with the -T argument.
How we are able to figure out which functions are able to be attached to is by first examing the target executable with `objdump -T simple_c_example/out.o | awk '{print $6} >simple_c_example/objdump_of_example.txt`.
The file will be a list of dynamically linked functions that the executable will access.

To run the script type, `objdump_parser.py --obj_path <path to txt file>`.
This will create 3 files, these files were used to build the details of the `simple_example.c` file.
To execute our code you do not need to use the objdump parser, it is there because we used it to develop DynamoRIO code faster.
The `chromium_example.c` file is an example of how many functions we can attach to during runtime and emphasizes why the script is useful.


## Docker Instructions

If you are using the docker image then the install, compilation, and environment variables have already been set up.
The only thing a Docker user must do differently is when running the code, the user must use the `make docker` command.
DynamoRIO requires the argument `-xarch_root` within a Docker or QEMU environment. 