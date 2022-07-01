# Instructions

This folder contains python scripts for training and testing model, captured audio attributes data from outgoing telemetric packets, and source data for parsing sorted by distance from speaker to microphone. 
To build your own model, first select a window size n (3, 5, 7, and 10), run `data_parsing_final.py` in `ParseSourceData` folder and set window size with `--window_size`, then move all generated python pickle file data into `ParsedData`. Or you can directly use pickle data inside `ParseData` for running `classification_final.py`. 
Running `classification_final.py` trains a classification model for distinguishing 6 different background activities, saves the best performed model and generates confusion matrix for validation set, evaluation set I and II.
Running `classification_final.py` with arguments:
- `--gpu`: if you have CUDA and GPU resources, use this flag
- `--window_size`: specify window size
- `--max_epoch`: set max epochs to train
- `--ep_log_interval`: set log output frequency
- `--lrn_rate`: set up learning rate

For example, run `python classification_final.py --window_size 5` to use cpu and default options to run. 

### Python requirements

BackgroundActivityClassifier requires the following packeges in requirements.txt. Please use `pip install -r ./requirements.txt` to install the dependencies.
To install pytorch, please use `conda install pytorch torchvision -c pytorch`.


### Python file explanation

- `ParseSourceData/data_parsing_win#.py` parse raw data from our collected dataset into window size = n
- `classification_final.py` takes parsed pickle data files, perform training and testing.


### Directories

- `RawData`: preprocessed audio metrics data collected from Webex Client in Windows
- `ParseSourceData`: sorted RawData by distance from speaker to microphone and to be parsed
- `ParsedData`: parsed source data in .pkl format, ready for use in Classification.py training
