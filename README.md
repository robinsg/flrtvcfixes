# Download AIX iFixes based on FLRTVC report


Run the following to download the ifices to /usr4/ifix directory

```
$ python3.9 flrtvcfixes.py | grep -i ".tar$" | while read IFIX; do sudo wget -P /usr4/ifix ${IFIX}; done
```

Hipers will usually reference a folder so just download the fix file assocuated with the AIX versions and SP level. e.g.<br>
https://aix.software.ibm.com/aix/ifixes/ij46487/<br>

Some security fixes require downloading file from MRS e.g. <br>
https://www.ibm.com/resources/mrs/assets?source=aixbp<br>
