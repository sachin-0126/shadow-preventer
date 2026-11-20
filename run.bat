@echo off
title SHADOW PREVENTER - Crimathon Saveetha Engineering College
echo =====================================================================
echo                SHADOW PREVENTER - SOC DEFENSE SYSTEM                 
echo             Crimathon Project - Saveetha Engineering College         
echo =====================================================================
echo.
echo Initializing database and starting Flask security server...
echo.
python seed_data.py
python app.py
pause
