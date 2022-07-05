# Parse the files gathered from debugging

This script was used to parse the output files gathered from the debugger.
File paths are given as inputs to the script and are then able to correlate timestamps with the raw data.
The timestamps from Webex are in a different timezone than the timestamps gathered from our machine so we add an integer to the epoch to correct this inconsistency.

# Run the code

To run the code enter the command, `python3 debug_file_parser.py <path to raw data> <path to timestamps> <path to results file>`.

An example command is, `python3 debug_file_parser.py ../../datasets/data_example2/example_xdbg_log.txt ../../datasets/data_example3/timestamp_example.txt ../../datasets/data_example1/25cm_tmp.txt`