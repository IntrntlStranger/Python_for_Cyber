# Importing the 'argparse' module to write a command-line interface that will take in filename inputs
import argparse

# Importing the 'sys' module to enable control over the flow of Python execution
import sys

# Creating an ArgumentParser object that will store all the necessary information that has to be passed from the python command-line
parser = argparse.ArgumentParser(prog="IOC Scanner",
                                 usage="Scanning the given logs for IOCs",
                                 description="Insert the log file to be scanned and then the file where to save the unflagged artifacts")


# Filling the ArgumentParser with the information about the arguments of the program
parser.add_argument("--log", type=str, required=True, help="Path to the log file")
parser.add_argument("--iocs", type=str, required=True, help="Path to the IOCs file")
parser.add_argument("--out", type=str, required=True, help= "Path to save the suspicious IPs")


# Telling the parser to collect and interpret the command-line input (done by "parse.args()" method) and then store it in the variable "args"
# The "args" variable or "container" can be accessed by args.log, args.iocs that are down in the next block of code
args = parser.parse_args()


# Error handling block - sys.exit() terminates the execution of the code if there's an error
try:
# Opening and reading the file from the user input and redacting the newline character "/n"
    with open(args.log, "r") as file:
        log_data = [line.strip() for line in file.readlines()]
except FileNotFoundError:
    print("Check if the log file is there!")
    sys.exit(1)

# Error handling block
try:
    with open(args.iocs, "r") as file:
        ioc_data = [line.strip() for line in file.readlines()]
except PermissionError:
    print("Check the file permissions!")
    sys.exit(1)


# Set to store the findings that didn't match the IOCs file data - no duplicates
sus_artifacts = set()

# Iterating through the log files for matching findings to the known IOC file, rest go to sus_artifacts
for data in log_data:
    if data in ioc_data:
        print(f"{data} is a known IOC")
    else:
        sus_artifacts.add(data)

# Error handling block
try:
# Saving the suspicious findings to a file for further investigation
    with open(args.out, "w") as file:
        for data in sus_artifacts:
            file.write(f"{data}\n")
except IOError:
    print(f"Could not write to {args.out}. Here are the suspicious items:")
    for data in sus_artifacts:
        print(data)

else:
    print("IOC scan complete!")
    print(f"Unmatched findings saved in {args.out}")

