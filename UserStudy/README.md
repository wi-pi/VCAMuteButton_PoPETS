# UserStudy Survey and Analysis

This folder contains user study responses from recruited participants from Prolific. 
For multi-option questions, we presented the distribution of selected answers. For open-ended questions, two researchers independently coded the answers and we presented the distribution of answers in coded form. 
We used Cohen's kappa coefficients to measure the reliability of our Codec. Running `main.py` analyzes all user study responses and generates histogram graphs for our paper. Running `cohen_kappa.py` gives the cohen's kappa coefficients for 3 open-ended questions in our user study. 

# csv file explanation

- `clean_survey_file_total.csv` contains user study answers of those participants who passed attention checkers and gave complete answers.
- `Coding Answers.xlsx` contains coding results for 3 open-ended questions coded by two researchers separately.
- `Q61Cohen.csv`, `Q62Cohen.csv`, `Q104Cohen.csv` contains the first 30 coding answers by two researchers for calculating Cohen parameters.

# non-script file explanation

- `webex-dump.json` contains one example of telemetric packets retrieved from Webex outgoing traffic.
- `user-study-survey.pdf` contains the full user study we used for accessing participants' understanding and expectations towards mute button.
- `requirements.txt`: dependency requirements for python.
- `Figures` contains generated plots after running `main.py`.

# py files explanation

- `cohen_kappa.py` for calculating Cohen's kappa coefficients, which is used to measure inter-rater reliability.
- `main.py`: sanitizing user_study_total.csv file and draw plots fo each question.