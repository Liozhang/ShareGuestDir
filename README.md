# ShareGuestDir
A python base tool for easily open Guest account and setting share folder.

# Simple UI for this tool
* When running in CMD
  
![ShareGuestDir2.1](ShareGuestDir2.1.png)

* When After running
  
![ShareGuestDir2.2](ShareGuestDir2.2.png)

# Simple requirements
* Python >= 3.9
* Win10 CMD with Administrator privileges

# Simple for run
```
python ShareGuestDir.py
```

# Simple to build a `.exe` program
Build A exe in Windows 10 CMD with pyinstaller and same python version and same packages
```
python -m pip install pyinstaller

pyinstaller --onefile ShareGuestDir.py -n ShareGuestDir2
```
