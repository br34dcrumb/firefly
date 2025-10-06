import argparse
import time
import patoolib
import subprocess
from modules.filesystem import FileSystem as FS

BLUE = '\033[94m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
ENDC = '\033[0m'

class VersionDetector:
    def __init__(self, file_path):
        self.file_path = file_path
        self.version_dict = {}

    def extract_gztar(self, extract_dir):
        print(f'{YELLOW}[*] Extracting {self.file_path[:12]}... to {extract_dir}{ENDC}')
        t1 = time.time()
        patoolib.extract_archive(self.file_path, outdir = extract_dir, verbosity=-1)
        t2 = time.time()
        print(f'{YELLOW}[*] Extraction completed{ENDC}')
        print(f'{YELLOW}[*] Extraction time: {round((t2 - t1), 3)}s{ENDC}\n')  
        self.analysis_basedir = extract_dir
    
    def string_analyser(self):
        t1 = time.time()
        print(f'{BLUE}[*] Performing string analysis{ENDC}')
        vd = VersionDetection(self.analysis_basedir)
        vd.search_file_strings()
        self.version_dict = vd.grep_version()
        t2 = time.time()
        print(f'{BLUE}[*] String analysis completed{ENDC}')
        print(f'{BLUE}[*] String analysis time: {round((t2 - t1), 3)}s{ENDC}\n')
        return self.version_dict

class VersionDetection:
    def __init__(self, root_path):
        self.root_dir = root_path
        self.BIN_ARRAY = []
        self.matching_files_dict = {}
        self.identified = {}
        self.files = []

    def search_file_strings(self):
        fb = open("bin_version_strings.cfg", "r")
        total_lines = len(fb.readlines())
        fb.seek(0)
        for i in range(total_lines):
            k = fb.readline()[:-2].split(';')
            if (len(k) < 4) and (('live' in k) or ('no_static' in k)):
                pass
            self.BIN_ARRAY.append(k[0])

        fs = FS(self.root_dir)
        files = fs.get_all_binaries() + fs.get_all_libraries()
        
        for file_path in files:
            try:
                content = subprocess.check_output(['strings', file_path], text=True)

                for value in self.BIN_ARRAY:
                    if value in content:
                        if value not in self.matching_files_dict:
                            self.matching_files_dict[value] = []
                        if value not in self.matching_files_dict[value]:
                            self.matching_files_dict[value].append(file_path)
            except (IOError, UnicodeDecodeError) as e:
                print(f"Error processing file {file_path}: {e}")

    def grep_version(self):
        fb = open("bin_version_strings.cfg", "r")
        for i in self.BIN_ARRAY:
            k = fb.readline()[:-2].split(';')

            try: 
                STRICT = k[1]
              # LIC = k[2] # not used
                BIN_NAME = k[0]
              # CSV_REGEX = k[4] # not used

                if STRICT == 'zgrep' or STRICT == 'strict':
                    pass

                VERSION_IDENTIFIER = k[3].lstrip("'").rstrip("'")
                
                ## Case: multi_grep -> One binary has mutiple ways to grep version
                if "&&" in VERSION_IDENTIFIER:
                    VERSION_IDENTIFIER = VERSION_IDENTIFIER.split("&&")
                else:
                    VERSION_IDENTIFIER = VERSION_IDENTIFIER

                if type(VERSION_IDENTIFIER) == str:
                    VERSION_IDENTIFIER = VERSION_IDENTIFIER.replace('\\',  '')

                    for file_path in self.matching_files_dict.get(BIN_NAME, []):
                        command = f"strings {file_path} | grep -o -a -E {VERSION_IDENTIFIER} | head -1 2>/dev/null || true"
                        try:
                            # Run the strings and grep commands using subprocess
                            output_bytes = subprocess.check_output(command, shell=True)
                            output_str = output_bytes.decode(errors='ignore').strip()

                            # Process the output as needed
                            if output_str != "":
                                if BIN_NAME not in self.identified.keys():
                                    self.identified[BIN_NAME] = []
                                if output_str not in self.identified[BIN_NAME]:
                                    self.identified[BIN_NAME].append(output_str)
                                break

                        except subprocess.CalledProcessError as e:
                            # print(f"Error processing file {file_path}: {e}")
                            break
                else:
                    for i in VERSION_IDENTIFIER:
                        VERSION_FINDER = i.replace('\\',  '').replace("~`", '\`') # hot-fix for back-ticks, only one in the cfg file for now
                        for file_path in self.matching_files_dict.get(BIN_NAME, []):
                            VERSION_FINDER = VERSION_FINDER.rstrip('"').lstrip('"') if VERSION_FINDER[0] == '"' else VERSION_FINDER
                            command = f"strings {file_path} | grep -o -a -E \"{VERSION_FINDER}\" | head -1 2>/dev/null || true"
                            try:
                                output_str = subprocess.check_output(command, shell=True).decode(errors='ignore').strip()
                                # Process the output as needed
                                if output_str != "":
                                    if BIN_NAME not in self.identified.keys():
                                        self.identified[BIN_NAME] = []
                                    if output_str not in self.identified[BIN_NAME]:
                                        self.identified[BIN_NAME].append(output_str)
                            
                            except subprocess.CalledProcessError as e:
                                # print(f"Error processing file {file_path}: {e}")
                                break
                        
            except:
                pass
        return self.identified

def main():
    parser = argparse.ArgumentParser(description='Version Detector \n ======================== \n Automatically extracts the FS and analyses the binaries for version strings.')
    parser.add_argument('-f', '--file', type=str, help='Path to file (*.tar.gz)')
    parser.add_argument('-o', '--output', type=str, help='Output directory')
    args = parser.parse_args()

    if args.file:
        vd = VersionDetector(args.file)    
        vd.extract_gztar(args.output) if args.output else vd.extract_gztar('_extracted')
        v_dict = vd.string_analyser()

        print(f'{BLUE}[*] Version strings found:{ENDC}')
        for i in v_dict.keys():
            print(f'{RED}{i}:{ENDC}')
            for j in v_dict[i]:
                print(f'\t{GREEN}{j}{ENDC}')
            print()

    else:
        parser.print_help()

    

if __name__ == '__main__':
    main()