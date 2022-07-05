# Play the videos for Webex.

This script will automatically play a video at the start of the minute intervals that Webex uses.
There is no good way to predict where exactly a video finishes within the time interval.
Therefore, we need to log when the video starts and ends.
We also want to have a forced waiting period where we retrieve the time of the last sent packet and wait for Webex to send out another packet after the last one.
The code then starts playing the video as soon as it registers that a packet has been sent out after a waiting period.
This way we do not have any overlapping data points.
Our method also ensures that we can capture the maximum amount of data that we can per session.

# How to run the script

Once you have installed everything, you can run the script as so,

``` python3 play_video_script.py --vlc_path <path to vlc library (optional)> --log_file <path to log file> --videos_dir <path to directory containing videos> --seen_before <path to tracker file which manages which videos to play.>```

An example command is,

``` python3 play_video_script.py --log_file ./log.txt --videos_dir  ../../../datasets/video_data_example --seen_before ./played_vids.txt```


# Docker Specifc Information

Currently our docker image does not support videos being played.
The reason being is that all operating systems need to interface with the container differently which limits how we can generalize the container interfacing.
If the user would like to run our script the would need to install [x11docker](https://github.com/mviereck/x11docker).
This wrapper is able to connect a container with a machine's interfaces that will only work on Linux.
If the reader would like to do this, they would need to also install `vlc` within the container.  