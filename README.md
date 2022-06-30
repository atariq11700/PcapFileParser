# How to build and run
1. Building
    1. Using Vscode
        * Open the command pallete using control+p (or the mac equivalent)
        * Type right caret (>)
        * Type run task
        * Select the task `build project`
    2. Using g++ and the command line
        * navigate to the the project source directory
            * should contain the `src`, `data`, `bin`, `test`, and `tools` directories
        * run `g++ -std=c++17 -O3 -D linux src/main.cpp src/log/*.cpp src/network/*.cpp src/network/protocols/*.cpp -o bin/parser`
2. Running
    1. Run the program in the bin folder, and pass in all files as command line arguements
    2. The program will display a file counter as it proccesses each file and then output a file called `output.txt` with only the analysis of the files. It will also print this to the screen.  
        * Ex. To run it against a single file, lets say test_data.pcap, you would run `./bin/parser test_data.pcap`
        * Ex. To run it against all files in the public data directory, you would run `./bin/parser /home/public/data/*` 

    \**NOTE*\* some of the files are big, give some time to process
