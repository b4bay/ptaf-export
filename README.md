# Export data tool for PT AF
This tool can be used for export data about attacks and rules from PT AF.

The tool is designed to use for reporting by [ptaf-report](https://github.com/b4bay/ptaf-report). 

# How to use
1. Copy `run.py` to PT AF, for example by wget:
    ```
    $ wget https://raw.githubusercontent.com/b4bay/ptaf-export/master/run.py
    ```
2. Run script with `sudo` using options needed:

    ```
    $ sudo /opt/waf/python/bin/python ./run.py -h
    usage: run.py [-h] [-w WEBAPP_NAME] [--range RANGE] [--end_date END_DATE]
    
    Export data from PT AF
    
    optional arguments:
      -h, --help            show this help message and exit
      -w WEBAPP_NAME, --webapp WEBAPP_NAME
                            webapp name, "Any" by default
      --range RANGE, -r RANGE
                            Data range in days from start date, 7 by default
      --end_date END_DATE, -e END_DATE
                            End of exported timeframe, in YYYY-MM-DD form (e.g.
                            2020-05-01) or just "today". Default is "today"
    
    ```
3. Archive all the data and copy them out of the PT AF to future use with [ptaf-report](https://github.com/b4bay/ptaf-report). 
    ```
    $ tar czvf export_data_\`date +"%Y-%m-%d"\`.tar.gz *.csv
    ```