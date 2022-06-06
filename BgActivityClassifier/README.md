# Instructions

This folder contains python scripts for training and testing model, captured audio attributes data from outgoing telemetric packets, and source data for parsing sorted by distance from speaker to microphone. 
To build your own model, first select a window size n (3, 5, 7, and 10) and run `data_parsing_win#.py` in `ParseSourceData` folder, then move all generated python pickle file data into `ParsedData`. Or you can directly use pickle data inside `ParseData` for running `classification_final5.py`. Before running classification, check if `Log` folder exists in your working directory. If not, create a new directory named `Log` under the same folder of `classification_final5.py`. 
Running `classification_final5.py` trains a classification model for distinguishing 6 different background activities, saves the best performed model and generates confusion matrix for validation set, evaluation set I and II.
If you want to use window size other than `5`, please follow the TODO instructions inside `classification_final5.py` script to modify the model structure and input data source. 

### Python requirements

BackgroundActivityClassifier requires the following packeges in requirements.txt. Please use `pip install -r ./requirements.txt` to install the dependencies.
To install pytorch, please use `conda install pytorch torchvision -c pytorch`.


### Python file explanation

- `ParseSourceData/data_parsing_win#.py` parse raw data from our collected dataset into window size = n
- `classification_final#.py` takes parsed pickle data files, perform training and testing. classification_final5.py file is for training with window length = 5. Please follow the TODOs to modify for different window lengths.


### Directories

- `RawData`: preprocessed audio metrics data collected from Webex Client in Windows
- `ParseSourceData`: sorted RawData by distance from speaker to microphone and to be parsed
- `ParsedData`: parsed source data in .pkl format, ready for use in Classification.py training
