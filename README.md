# Download AIX iFixes based on FLRTVC report

The output from flrtvc.ksh can contain multiple rows for a file set. This python script will remove duplicate lines<br>
and filter the row we are intersted in by capturing the file set with a CVSS Base Score equal tp or higher than the <br>
minimum cvss base score we pass to the script.<br><br>

An example of running flrtvc would be:

```
./flrtvc.ksh -d , > vc`date +"%Y%M%d-%H%M%S"`.txt
```
Once we have the file generated we can use this as input to flrtcvfixes.py<br><br>

Run the following to download the ifices to /usr4/ifix directory

```
$ sudo python3 flrtvcfixes.py  vc20240103-090138.txt 7 /usr4/ifix/
```
vc20240103-090138.txt is the name of the output file generated by flrtvc.ksh<br>
7 is the minimum CVSS Base Score to include in the output<br>
/usr4/ifix/ is the destination directory used to store the flrtvcapars.txt file<br>

This flrtvcapars.txt contains a row for each files set to be patched along with the Bulletin URL and Download URL.<br><br>

Most of the security APAR fixed reference a tar file in the Download URL column. The script will attept to download the tar files<br>
in to the selected download directory.<br><br>

Some security fixes require manually downloading file from MRS e.g. <br>
https://www.ibm.com/resources/mrs/assets?source=aixbp<br>
In this instance open the Bulletin URL which will provide a link to the download.<br>

Any hiper fixes will usually reference a folder so just manually download the fix file assocuated with the AIX versions and SP level. e.g.<br>
https://aix.software.ibm.com/aix/ifixes/ij46487/<br>
