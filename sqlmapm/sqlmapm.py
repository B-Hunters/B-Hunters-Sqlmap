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
from bson.objectid import ObjectId
from functools import partial

def generate_random_filename():
    temp_dir = tempfile.gettempdir()
    random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Generate a random string
    filename = os.path.join(temp_dir, random_name)
    return filename

def sqlmap_header_args(headers):
    """The arguments that give sqlmap the session headers.

    Sqlmap takes them as ``--headers`` and sends them with every
    request it makes.  Several headers are separated by a newline.
    """
    if not headers:
        return []
    return ["--headers", "\n".join(f"{name}: {value}" for name, value in headers.items())]

def runsqlmap(url,headers=None):
    
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
                    "--answers='problems=y,involving it=n'",
                    "--batch", 
                    "--disable-coloring", 
                    "--random-agent", 
                    # The scan hands sqlmap the root of the target, which
                    # carries no parameter of its own: the parameters live
                    # in the pages the target links to.  The level, the
                    # risk and the technique set say how deep sqlmap looks,
                    # and the crawl says where it looks.
                    "--level=3",
                    "--risk=2",
                    "--crawl=2",
                    "--technique=BEUSTQ",
                    # An application that answers 401 is protected, not
                    # broken: sqlmap must not stop the run because of it.
                    "--ignore-code=401",
                    "--threads=4",
                    f"--output-dir={outputdir}", 
                    "--tamper=between,randomcase,space2comment"
                ] + sqlmap_header_args(headers), stdout=subprocess.PIPE)
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
    if result==[] or result=="":
        return [],[]
        
    return url,result

def runsqlmapsubdomain(url,headers=None):
    
    outputdir=generate_random_filename()
    result=""
    try:
        # for i in data:
        if url != "":
            try:
                # Disable certificate verification with verify=False
                p1 = subprocess.Popen([
                    "python3", 
                    "/app/sqlmap/sqlmap.py", 
                    "-u", url, 
                    "-b", 
                    "-o", 
                    "--batch", 
                    "--answers='problems=y,involving it=n'",
                    "--disable-coloring", 
                    "--random-agent", 
                    "--risk", "3",
                    "--level", "3",
                    "--crawl","3",
                    "--forms",
                    f"--output-dir={outputdir}", 
                    "--tamper=between,randomcase,space2comment,space2morehash"
                ] + sqlmap_header_args(headers), stdout=subprocess.PIPE)
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
    if result=="":
        return []

    return [url,result]

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
        },
        {
            "type": "subdomain", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
               
    def url_list(self, source, url):
        """The URL list the crawler produced.

        The copy in the object store is temporary: Karton's garbage
        collector removes it once no live task refers to it, so a scanner
        that starts late finds it gone and the scan dies without looking
        at anything.  The database holds the same list, and it is what the
        scanner falls back to.
        """
        try:
            return self.backend.download_object(
                "bhunters",
                f"{source}_" + self.scanid + "_" + self.encode_filename(url),
            )
        except Exception as exc:
            self.log.error(f"the URL list is not in the bucket: {exc}")
            document = self.db["links"].find_one(
                {
                    "report_id": ObjectId(self.report_id),
                    "source": {"$regex": source, "$options": "i"},
                }
            )
            if document is None:
                raise
            links = document.get("Links") or []
            self.log.info(f"using {len(links)} link(s) from the database")
            return "\n".join(str(link) for link in links).encode()

    def checklinksexist(self, subdomain, links):
        """The links of this scanner that this scan has not checked yet.

        The shared base class in the published ``b-hunters`` package keys
        its record by host, and a host can have several scans: the second
        scan of a host reads the first scan's record and skips the URLs it
        has never tested.  The lookup is repeated here until a release of
        the package carries the fix.
        """
        missing_links = []
        if links == "":
            return []
        if isinstance(links, str):
            links = links.splitlines()

        links = [link for link in links if is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        scanid = getattr(self, "scanid", "") or ""
        if not scanid:
            document = self.db["domains"].find_one({"Domain": subdomain})
            if document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = document["Scanid"]

        document = self.db["scans"].find_one({"_id": ObjectId(scanid)})
        if document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing = document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing]
        if missing_links:
            self.db["scans"].update_one(
                {"_id": ObjectId(scanid)},
                {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}},
            )
        return missing_links

    def scan(self,url,source,headers):
        try:    
            data=self.url_list(source, url)
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
        data2=self.checklinksexist(self.subdomain, [link for link in p4.stdout.read().decode("utf-8") if is_on_target(self.subdomain, link)])
        p4.stdout.close()
        
        # # URL encode each entry in data2
        dataencoded = [url.replace(' ', '%20') for url in data2 if url]
        
        result=[]
        try:
            if data2 != []:
                pool = multiprocessing.Pool(processes=int(os.getenv("process_num","15")))
                result_array = pool.map(partial(runsqlmap, headers=headers), dataencoded)
                pool.close()
                pool.join()
                for res in result_array:
                    if res[1]!="" and res[1]!=[]:
                        result.append(res)

            # result=runsstichecker(data2)
        except Exception as e:
            self.log.error(e)
            raise Exception(e)
        os.remove(filename)
        return result
        
        RtTNyX9Eeu8W
    def process(self, task: Task) -> None:
        url = task.payload["data"]
        subdomain=task.payload["subdomain"]
        subdomain = re.sub(r'^https?://', '', subdomain)
        subdomain = subdomain.rstrip('/')
        self.subdomain=subdomain
        source=task.payload["source"]
        self.update_task_status(subdomain,"Started")
        self.log.info("Starting processing new url")
        self.log.warning(f"{source} {url}")
        report_id=task.payload_persistent["report_id"]
        self.report_id=report_id
        self.scanid=task.payload_persistent["scan_id"]
        try:
            headers=self.auth_headers(task)
            if source == "subrecon":
                result=runsqlmapsubdomain(url,headers)
            else:
                        
                result=self.scan(url,source,headers)
            self.waitformongo()    
            db=self.db
            collection=db["reports"]
            if result !=None and result !=[]:
                collection.update_one({"_id": ObjectId(report_id)}, {"$push": {f"Vulns.SQLMap": {"$each": result}}})
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
        


def is_on_target(subdomain, link):
    """Is the link part of the target?

    A crawler collects the third-party links of a page as well.  A
    scanner that is handed the raw list probes those hosts instead of the
    target.  The comparison ignores the scheme and the path, and it takes
    the port into account, because the target is named as host:port.
    """
    if not link:
        return False
    target_host, _, target_port = (subdomain or "").partition(":")
    target_host = target_host.lower()

    candidate = str(link).strip()
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    host, _, port = candidate.partition(":")

    if host.lower() != target_host:
        return False
    if target_port and port != target_port:
        return False
    return True
