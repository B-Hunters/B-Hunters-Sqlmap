from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import shutil
import re
import os

import multiprocessing
import warnings
import requests
import requests.exceptions
import tempfile
import random
import string
def generate_random_filename():
    temp_dir = tempfile.gettempdir()
    random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Generate a random string
    filename = os.path.join(temp_dir, random_name)
    return filename

def runsqlmap(url):
    
    outputdir=generate_random_filename()
    result=""
    try:
        # for i in data:
        if url != "":
            try:
                # python3 ${tools}/sqlmap/sqlmap.py -m .tmp/tmp_sqli.txt -b -o --smart --batch --disable-coloring --random-agent --output-dir=vulns/sqlmap 2>>"$LOGFILE" >/dev/null
                # Disable certificate verification with verify=False
                p1 = subprocess.Popen([
                    "python3", 
                    "/app/sqlmap/sqlmap.py", 
                    "-u", url, 
                    "-b", 
                    "-o", 
                    "--smart", 
                    "--batch", 
                    "--disable-coloring", 
                    "--random-agent", 
                    f"--output-dir={outputdir}", 
                    "--tamper=between,randomcase,space2comment"
                ], stdout=subprocess.PIPE)
                try:
                    output, _ = p1.communicate(timeout=int(os.getenv("process_timeout","600")))  # 10 minutes timeout
                except subprocess.TimeoutExpired:
                    p1.kill()
                if os.path.isdir(outputdir):
                    subfolders = [f.path for f in os.scandir(outputdir) if f.is_dir()]
                    if subfolders:
                        log_folder = subfolders[0]
                        log_path = os.path.join(log_folder, "log")
                        if os.path.getsize(log_path) > 0:
                            with open(log_path, 'r') as file:
                                result = file.read()
            except requests.exceptions.RequestException:
                pass
        
    except Exception as e:
        raise Exception(e)
        # result=[]
    return url,result

class sqlmapm(BHunters):
    """
    B-Hunter SQLMap developed by Bormaa
    """

    identity = "B-Hunters-SQLMap"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "paths", "stage": "scan"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
               
    def scan(self,url,source):
        try:    
            data=self.backend.download_object("bhunters",f"{source}_"+self.encode_filename(url))
        except Exception as e:
            raise Exception(e)


        filename=self.generate_random_filename()+".txt"
        with open(filename, 'wb') as file:
            # for item in data:
            file.write(data)

        p1 = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep","="], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()

        p3 = subprocess.Popen(["uro","--filter","hasparams"], stdin=p2.stdout, stdout=subprocess.PIPE)
        p2.stdout.close()
        p4 = subprocess.Popen(["qsreplace","FUZZ"], stdin=p3.stdout, stdout=subprocess.PIPE)
        p3.stdout.close()
        data2=self.checklinksexist(self.subdomain,p4.stdout.read().decode("utf-8"))
        
        # # URL encode each entry in data2
        dataencoded = [url.replace(' ', '%20') for url in data2 if url]
        
        result=[]
        try:
            if data2 != []:
                pool = multiprocessing.Pool(processes=int(os.getenv("process_num","15")))
                result_array = pool.map(runsqlmap, dataencoded)
                pool.close()
                pool.join()
                for res in result_array:
                    if res[1]!="":
                        result.append(res)

            # result=runsstichecker(data2)
        except Exception as e:
            self.log.error(e)
            raise Exception(e)
        os.remove(filename)
        return result
        
        
    def process(self, task: Task) -> None:
        url = task.payload["data"]
        subdomain=task.payload["subdomain"]
        self.subdomain=subdomain
        source=task.payload["source"]
        self.update_task_status(subdomain,"Started")
        self.log.info("Starting processing new url")
        self.log.warning(f"{source} {url}")
        try:
                
            result=self.scan(url,source)
            db=self.db
            collection=db["domains"]
            if result !=None and result !=[]:
                collection.update_one({"Domain": subdomain}, {"$push": {f"Vulns.SQLMap": {"$each": result}}})
                resultarr=[]
                for i in result:
                    resultarr.append(" ".join(i))
                output="\n".join(resultarr)
                self.send_discord_webhook("SQL Injection",output,"main")
        except Exception as e:
            self.log.error(e)
            self.update_task_status(subdomain,"Failed")
            raise Exception(e)
        self.update_task_status(subdomain,"Finished")
        