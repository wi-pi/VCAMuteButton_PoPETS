# Parse the files gathered from debugging

This script was used to parse the output files gathered from the debugger.
File paths are given as inputs to the script and are then able to correlate timestamps with the raw data.
The timestamps from Webex are in a different timezone than the timestamps gathered from our machine so we add an integer to the epoch to correct this inconsistency.

# Run the code

First, as with all of the python scripts, you have to install all of the packages.
To do that, you run the command `pip3 install -r requirements.txt` in the main directory of the repository.
To run the code enter the command, `python3 debug_file_parser.py <path to raw data> <path to timestamps> <path to results file>`