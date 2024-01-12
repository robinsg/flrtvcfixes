# Download AIX iFixes based on FLRTVC report


Run the following to download the ifices to /usr4/ifix directory

```
$ python3.9 flrtvcfixes.py | grep -v hiper | while read IFIX; do sudo wget -P /usr4/ifix ${IFIX}; done
```
