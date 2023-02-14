# Gimme
Gimme is a log analysis tool written in Python that can extract various information from log files, including IP addresses, email addresses, file paths, filenames, URLs, domains, and dates.

## Usage
To use Gimme, simply run the gimme.py script and provide one or more log files as input. You can specify which functionality you want to use by passing one or more arguments to the script. For example, to extract all available information from a log file called example.log, you can run:


python gimme.py -a example.log
The available command line options are:

<ul>
<li>-a: Extract all available information (emails, IPs, domains, URLs, and filenames) from the log file(s).</li>
<li>-e: Extract email addresses from the log file(s).</li>
<li>-i: Extract IP addresses from the log file(s).</li>
<li>-d: Extract domains from the log file(s).</li>
<li>-u: Extract URLs from the log file(s).</li>
<li>-f: Extract filenames from the log file(s).</li>
<li>-h: Display a help menu with available options.</li>
</ul>

You can provide one or more log files as input by specifying their paths as arguments after the options. For example, to extract email addresses and domains from two log files called access.log and error.log, you can run: 
<br><br>
``python gimme.py -e -d access.log error.log``
<br><br>
The results will be printed to the console in a formatted manner, with any matches highlighted in red.

## Example Log File
An example log file containing IPs, emails, file paths, names, dates, and domains is included in this repository as example.log. You can use this file to test the functionality of Gimme.

## Requirements
Gimme requires Python 3 to run, and the following packages are also required:
<ul>
<li>argparse</li>
<li>colorama</li>
<li>re</li>
</ul>
You can install these packages using pip by running:


``pip install argparse colorama``

## Author
Gimme was created by shamoo0.

## License
Gimme is licensed under the MIT License. Feel free to use, modify, and distribute the code as you see fit.
