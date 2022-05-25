# Python requirements

BackgroundActivityClassifier requires the following packeges in requirements.txt. Please use `pip install -r ./requirements.txt` to install the dependencies.


# Python file explanation

- data_parsing_win#.py parse raw data from our collected dataset into window size = n
- classification_final#.py takes parsed pickle data files, perform training and testing. classification_final5.py file is for training with window length = 5. Please follow the TODOs to modify for different window lengths.


### Directories

- `RawData`: preprocessed audio metrics data collected from Webex Client in Windows
- `ParseSourceData`: sorted RawData by distance from speaker to microphone and to be parsed
- `ParsedData`: parsed source data in .pkl format, ready for use in Classification.py training
