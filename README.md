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
    options for submit:
        -d	Specifies directory with malware samples. (Can't combine with -f)
        -f	Specifies one malware sample. (Can't combine with -d)
        -o	Specifies output directory name for dowloaded pcaps

    --download	    Download all files from specified report directory
    options for download:
        -f	Specifies one folder with report files.
        -o	Specifies output directory name for dowloaded pcaps

    --get	Downloads n malware samples of specified family
    options for get:
        -m	Specifies malware family.
        -l	Specifies how many samples of given family we want.
        -d	Specifies output directory name for dowloaded samples
        --now Immediately after submit downloads pcap files.

    --all	Downloads n malware samples of specified family and runs analysis and than stores the pcap files
    options for all:
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

## Struktura archivu
* triage_client.py
* src/general.py
* src/report.py
* src/pcap_downloader.py
* src/sample_downloader.py
* example_families.txt
* README.md 
* requirements.txt
