# IEEE OUI local cache

Place the IEEE MA-L CSV public listing at `oui.csv` in this directory.

Official source:

`https://standards-oui.ieee.org/oui/oui.csv`

Module 5 reads this file locally and does not download registry data during a
wireless scan. If the file is unavailable or an OUI is not present, the API
returns `Unknown` with zero confidence.
