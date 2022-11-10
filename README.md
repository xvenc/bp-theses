# Tool for creating malware datasets

**Author:** Václav Korvas

The tool is used to automatically download malware samples from `bazaar.abuse.ch`, then analyze them using `tria.ge` and download the corresponding pcap files and reports. Whole folder with malware samples can be analyzed or just one malware sample. The samples can be also just send to the analysis without downloading the pcap file.

## Instalation
First you need to unzip the `dataset_creator.zip` file. On Linux, use the command `unzip dataset_creator.zip`. This will create a folder with the same name, with the source files, which you need to switch to. 

Next, using the command `pip install -r requirements.txt` you need to install all the necessary packages. After that, the program can be run using `python3 triage_client.py <arguments>`.

Program was tested on Ubuntu 20.04 and on Arch linux distribution.

## Usage
```
Usage: python3 triage_client.py [COMMAND] [OPTIONS]

Commands:
    --help          Show this help message and exists 
    --submit	    Submit file or whole directory to tria.ge
    Options for submit:
        -d	Specifies directory with malware samples. (Can't combine with -f)
        -f	Specifies one malware sample. (Can't combine with -d)
        -o	Specifies output directory name for dowloaded pcaps
		--now Immediately after submit downloads pcap files.

    --download	    Download all files from specified report directory
    Options for download:
        -d	Specifies one folder with report files. Folder mustn't contain other folders.
        -o	Specifies output directory name for dowloaded pcaps

    --get	Downloads n malware samples of specified family
    Options for get:
        -m	Specifies malware family.
        -l	Specifies how many samples of given family we want.
        -d	Specifies output directory name for dowloaded samples

    --all	Downloads n malware samples of specified family and runs analysis and than stores the pcap files
    Options for all:
        -m	Specifies malware family. Or .txt file with malware family names each on new line of the file
        -l	Specifies how many samples of given family we want.
        -o	Specifies output directory name for dowloaded pcaps
        -d	Specifies output directory for malware samples.
        --now Immediately after submit downloads pcap files.

Report files are automaticaly created. The file name is based on the input directory.
COMMAND arguments can't be combined.

```
## Examples
Here are some usage examples.
All these individual examples consist of 3 part:
* First is shown the content of the folder before the command is executed.
* Command execution and output.
* Folder contetn after the program execution.
```
Download malware, then upload to tria.ge and download pcaps
$ ls
example_family.txt  README.md  requirements.txt  src/  triage_client.py

$ python3 triage_client.py --all -m example_family.txt -l 1 -d malware -o pcaps --now

Queried 1 samples for family redlinestealer. Now the samples will be downloaded.
Downloaded malware sample: malware1.zip
Submitting files from directory: malware/redlinestealer
Submitted malware: malware1.zip
Downloading...
Downloaded pcap for malware1.zip
Queried 1 samples for family Mirai. Now the samples will be downloaded.
Downloaded malware sample: malware2.zip
Submitting files from directory: malware/mirai
Submitted malware: malware2.zip
Downloading...
Downloaded pcap for malware2.zip
Queried 1 samples for family Heodo. Now the samples will be downloaded.
Downloaded malware sample: malware3.zip
Submitting files from directory: malware/heodo
Submitted malware: malware3.zip
Downloading...
Downloaded pcap for malware3.zip

$ ls
example_family.txt  malware/  pcaps/  README.md  reports/  requirements.txt  src/  triage_client.py
```
```
Download malware samples for family redlinestealer
$ ls 
example_family.txt  README.md  requirements.txt  src/  triage_client.py

$ python3 triage_client.py --get -m RedLineStealer -d malware/ -l 2

Queried 2 samples for family redlinestealer. Now the samples will be downloaded.
Downloaded malware sample: malware4.zip
Downloaded malware sample: malware5.zip

$ ls
example_family.txt  malware/  README.md  requirements.txt  src/  triage_client.py
```
```
Submit directory for analysis but dont download the samples
$ ls 
example_family.txt malware/  README.md  requirements.txt  src/  triage_client.py

$ python3 triage_client.py --submit -d malware/redlinestealer/

Submitting files from directory: malware/redlinestealer/
Submitted malware: malware4.zip
Submitted malware: malware5.zip

$ ls
xample_family.txt  malware/  README.md  reports/  requirements.txt  src/  triage_client.py

```
## Struktura archivu
* triage_client.py
* src/general.py
* src/report.py
* src/pcap_downloader.py
* src/sample_downloader.py
* example_family.txt
* README.md 
* requirements.txt
