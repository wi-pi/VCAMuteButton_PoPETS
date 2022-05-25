# csv file explanation

- `user_study_total.csv` contains user study answers from all of our participants
- `clean_survey_file_total.csv` contains user study answers of those participants who passed attention checkers and gave complete answers
- `Coding Answers.xlsx` contains coding results for 4 open-ended questions coded by two researchers separately

- `Q61Cohen.csv`, `Q62Cohen.csv`, `Q104Cohen.csv` contains the first 30 coding answers by two researchers for calculating Cohen parameters.

# non-script file explanation

- `webex-dump.json` contains one example of telemetric packets retrieved from Webex outgoing traffic
- `user-study-survey.pdf` contains the full user study we used for accessing participants' understanding and expectations towards mute button
- `requirements.txt`: dependency requirements for python

# py files explanation

-`cohen_kappa.py` for calculating Cohen's kappa coefficients, which is used to measure inter-rater reliability
-`main.py`: sanitizing user_study_total.csv file and draw plots fo each question