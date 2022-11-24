# Tool for creating malware datasets

**Author:** Václav Korvas

The tool is used to automatically download malware samples from `bazaar.abuse.ch`, then analyze them using `tria.ge` and download the corresponding pcap files and reports. Whole folder with malware samples can be analyzed or just one malware sample. The samples can be also just send to the analysis without downloading the pcap file.

## Instalation
First you need to unzip the `dataset_creator.zip` file. On Linux, use the command `unzip dataset_creator.zip`. This will create a folder with the same name, with the source files, which you need to switch to. 

Next, using the command `pip install -r requirements.txt` you need to install all the necessary packages. After that, the program can be run using `python3 triage_client.py <arguments>`.

If you have your own account on `tria.ge` and want to use yours just change the variable **auth_api_key** in the file `triage_client.py` on line 13. You can find your authorization api key on this link: 
`https://tria.ge/account`. Otherwise my account with my api key will be used and you wont see the submitted samples on the `tria.ge` website.

Program was tested on Ubuntu 20.04 and on Arch linux distribution.

## Usage
The **main command** is the `--all` command. This command downloads `n` number of samples for each family, then it will upload all the samples to the `tria.ge` for analysis. And 2 pcap files will be downloaded from 2 analysis for each malware sample. The pcaps for one malware have same name but different endings `_1` and `_2`.
And the it will download all the pcaps and overview reports as .json file. The file with malware families needs to have each family name on new line. And it's better to look the family name on the website `bazaar.abuse.ch` and use the name what they use, because sometimes it doesnt work if the name is a bit different. It the zip archive is exampe with 15 family names.

Next command is `--submit` command. This command is for uploading single file or whole directory to the `tria.ge` for analysis. If whole directory is uploaded then `csv` log files are created. But if only simple file is uploaded no log files are created.

Command `--download` is used for downloading all pcap from `.csv` log file. This command only works if some `.csv` files were created using command `--submit`.

And last command `--get` is used to download `n` number of samples of specified family.


```
Usage: python3 triage_client.py [COMMAND] [OPTIONS]

Commands:
    --help          Show this help message and exists 
    --submit	    Submit file or whole directory to tria.ge
    Options for submit:
        -d	Specifies directory with malware samples. (Can't combine with -f)
        -f	Specifies one malware sample. (Can't combine with -d)
        -o	Specifies output directory name for dowloaded pcaps

    --download	    Download all pcaps for specified csv file 
    Options for download:
        -f	Specifies one .csv file.
        -o	Specifies output directory name for dowloaded pcaps

    --get	Downloads n malware samples of specified family
    Options for get:
        -m	Specifies malware family. If the family is 2 words, than it needs to be in "" ("Smoke Loader")
        -l	Specifies how many samples of given family we want. (Maximum is 1000)
        -d	Specifies output directory name for dowloaded samples

    --all	Downloads n malware samples of specified family and runs analysis and than stores the pcap files
    Options for all:
        -m	Specifies malware family. Or .txt file with malware family names each on new line of the file
        -l	Specifies how many samples of given family we want. (Maximum is 1000)
        -o	Specifies output directory name for dowloaded pcaps
        -d	Specifies output directory for malware samples.

Report and log files are automaticaly created. The file name is based on the input directory.
COMMAND arguments can't be combined.

```
## Examples
Here are some usage examples.
All these individual examples consist of 3 part:
* First is shown the content of the folder before the command is executed.
* Command execution and output.
* Folder content after the program was executed.
```
Download malware, then upload to tria.ge and download pcaps
$ ls
example_family.txt  README.md  requirements.txt  src/  triage_client.py

$ python3 triage_client.py --all -m example_family.txt -l 1 -d malware -o pcaps

Queried 1 samples for family redlinestealer. Now the samples will be downloaded.
Downloaded malware sample: malware1.zip
Submitting files from directory: malware/redlinestealer
Submitted malware for analysis: malware1.zip
Queried 1 samples for family Mirai. Now the samples will be downloaded.
Downloaded malware sample: malware2.zip
Submitting files from directory: malware/mirai
Submitted malware for analysis: malware2.zip
Queried 1 samples for family Heodo. Now the samples will be downloaded.
Downloaded malware sample: malware3.zip
Submitting files from directory: malware/heodo
Submitted malware for analysis: malware3.zip
Queried 1 samples for family AgentTesla. Now the samples will be downloaded.
Downloaded malware sample: malware4.zip
Submitting files from directory: malware/agenttesla
Submitted malware for analysis: malware4.zip
Downloading pcap for uploaded samples...
Downloading pcap files for directory: malware/redlinestealer
Downloaded pcap for malware1.zip
Downloading pcap files for directory: malware/mirai
Downloaded pcap for malware2.zip
Downloading pcap files for directory: malware/heodo
Downloaded pcap for malware3.zip
Downloading pcap files for directory: malware/agenttesla
Downloaded pcap for malware4.zip

$ ls
example_family.txt logs/  malware/  pcaps/  README.md  reports/  requirements.txt  src/  triage_client.py
```
```
Download malware samples for family redlinestealer
$ ls 
example_family.txt  README.md  requirements.txt  src/  triage_client.py

$ python3 triage_client.py --get -m "Smoke Loader" -d malware/ -l 2

Queried 2 samples for family redlinestealer. Now the samples will be downloaded.
Downloaded malware sample: malware4.zip
Downloaded malware sample: malware5.zip

$ ls
example_family.txt logs/  malware/  README.md  requirements.txt  src/  triage_client.py
```
```
Submit directory for analysis 
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
* src/csv_writer.py
* example_family.txt
* README.md 
* requirements.txt
