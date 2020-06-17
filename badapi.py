import argparse
import os
import re
from io import TextIOWrapper
import json

basepatterns = ["https:", "request"] #checks for outside communication

def searchfolder(dir: str) -> list:
    if dir[-1] != "/":
        raise Exception("Directory string not formatted correctly, expected '/' for trailing directory character, got {}".format(dir[-1]))
    folders, files = ([i for i in os.listdir(dir) if os.path.isdir(i)], [i for i in os.listdir(dir) if os.path.isfile(i)])
    file_objects = []
    for f in files:
        file_objects.append((open(f, 'r'), dir + f))
    if len(folders) == 0:
        return file_objects
    else:
        for folder in folders:
            file_objects = file_objects + searchfolder(dir + folder)
        return file_objects

def flagFileObject(fileobject: TextIOWrapper, filenamepath, patterns) -> list:
    tokens = re.split(r'/s+', fileobject.read())
    File = {"File": filenamepath, "issues": []}
    for token in tokens:
        for pattern in patterns:
            if re.search(pattern, tokens) != None:
                File["issues"].append({
                    "Pattern": pattern,
                    "Token": token
                })
    return File

def sniffPackage(packagepath:str, patterns:list):
    files = searchfolder(packagepath)
    Flags = []
    for f in files:
        processed = flagFileObject(f[0], f[1], patterns)
        if len(processed["issues"]) == 0:
            continue
        else:
            Flags.append(processed)
    for flagged in Flags:
        print("{0}\t{1} Issues".format(len(flagged["issues"])))
        for issue in flagged["issues"]:
            print("*\tPattern:{0}\t\ttoken:{1}".format(issue["Pattern"], issue["Token"]))
    return len(Flags)


if __name__ == "__main__":
    print("Author: Jonathan Martini, 2020")
    print(" /$$$$$$$   /$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$")
    print("| $$__  $$ /$$__  $$| $$__  $$ /$$__  $$| $$__  $$|_  $$_/")
    print("| $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$  | $$ ")
    print("| $$$$$$$ | $$$$$$$$| $$  | $$| $$$$$$$$| $$$$$$$/  | $$  ")
    print("| $$__  $$| $$__  $$| $$  | $$| $$__  $$| $$____/   | $$  ")
    print("| $$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$        | $$  ")
    print("| $$$$$$$/| $$  | $$| $$$$$$$/| $$  | $$| $$       /$$$$$$")
    print("|_______/ |__/  |__/|_______/ |__/  |__/|__/      |______/")
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", '--pattern', required=True, action='store_true', help="regex pattern to search")
    parser.add_argument("-bp", '--bulkpatternfile', action="store_true", help="loads regex patterns from file.txt")
    parser.add_argument('-dir', "--directory", required=True, action="store_true", help="directory to search")
    args = parser.parse_args()
    patterns = []
    if args.pattern:
        patterns.append(args.pattern)
    if args.bulkpatternfile:
        with open(args.bulkpatternfile, "r") as f:
            line = f.readline()
            while line:
                patterns.append(line.strip())
                line = f.readline()
    vulnerable = sniffPackage(args.directory, patterns)
    print("DONE!, {} Vulernable Scripts".format(vulnerable))






