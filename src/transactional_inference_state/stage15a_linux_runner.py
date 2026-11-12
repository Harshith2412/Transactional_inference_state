"""Native Linux runner for Stage 15A; never imported by the transaction runtime."""
from __future__ import annotations
import glob, hashlib, http.client, json, os, platform, shutil, signal, statistics, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any

def run(command:list[str],**kwargs:Any)->subprocess.CompletedProcess[str]:
    return subprocess.run(command,text=True,capture_output=True,timeout=kwargs.pop("timeout",30),**kwargs)
def request(port:int,path:str="/state",payload:dict[str,Any]|None=None)->dict[str,Any]:
    conn=http.client.HTTPConnection("127.0.0.1",port,timeout=5);body=None if payload is None else json.dumps(payload);conn.request("GET" if payload is None else "POST",path,body,{"Content-Type":"application/json"});result=json.loads(conn.getresponse().read());conn.close();return result
def wait(port:int)->None:
    for _ in range(100):
        try:request(port);return
        except Exception:time.sleep(.05)
    raise RuntimeError("service did not start")
def digest(value:Any)->str:return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def mutate(kind:str,port:int,density:int=1)->None:
    if kind=="tool":
        request(port,"/increment",{});request(port,"/set",{"key":"role","value":"admin"});request(port,"/append",{"value":"unsafe-operation"})
        for i in range(max(0,density-1)):request(port,"/set",{"key":f"k{i}","value":"unsafe"})
    else:
        request(port,"/authorize",{"value":"admin"});request(port,"/cache_write",{"key":"poison","value":"approved disclosure"})
        for i in range(max(0,density-1)):request(port,"/cache_write",{"key":f"k{i}","value":"unsafe"})
def start(kind:str,port:int)->subprocess.Popen[str]:
    process=subprocess.Popen([sys.executable,"-m","transactional_inference_state.stage15a_service",kind,"--port",str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True);wait(port);return process
def stop(pid:int)->None:
    try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
    except (ProcessLookupError,ChildProcessError):pass

def criu_trial(kind:str,port:int,root:Path,*,size_mb:int=0,density:int=1)->dict[str,Any]:
    images=root/f"{kind}-{size_mb}-{density}-{time.time_ns()}";images.mkdir(parents=True);process=start(kind,port)
    if size_mb:request(port,"/populate",{"megabytes":size_mb})
    initial=request(port);before=request(port,"/digest")["digest"];pid_before=process.pid
    mark=time.perf_counter_ns();dump=run(["criu","dump","-t",str(process.pid),"-D",str(images),"--shell-job","--tcp-established","--leave-running","-v4","-o","dump.log"]);checkpoint_ns=time.perf_counter_ns()-mark
    if dump.returncode:return {"backend":"CRIU","kind":kind,"success":False,"phase":"checkpoint","stderr":dump.stderr,"log":(images/"dump.log").read_text()[-4000:]}
    mutate(kind,port,density);mutated=request(port);mutated_digest=request(port,"/digest")["digest"];stop(process.pid)
    mark=time.perf_counter_ns();restore=run(["criu","restore","-D",str(images),"--shell-job","--tcp-established","-d","--pidfile",str(images/"pid"),"-v4","-o","restore.log"]);restore_ns=time.perf_counter_ns()-mark
    if restore.returncode:return {"backend":"CRIU","kind":kind,"success":False,"phase":"restore","stderr":restore.stderr}
    wait(port);restored=request(port);restored_digest=request(port,"/digest")["digest"];pid_after=int((images/"pid").read_text());existing=False;stop(pid_after)
    return {"backend":"CRIU","kind":kind,"success":initial==restored and before==restored_digest and before!=mutated_digest,"initial":initial,"mutated":mutated,"restored":restored,"pre_digest":before,"mutated_digest":mutated_digest,"restored_digest":restored_digest,"checkpoint_ns":checkpoint_ns,"restore_ns":restore_ns,"image_bytes":sum(x.stat().st_size for x in images.rglob("*") if x.is_file()),"pid_before":pid_before,"pid_after":pid_after,"port_preserved":True,"existing_socket_survived":existing,"new_connection_works":True,"reconnect_required":not existing,"size_mb":size_mb,"mutation_keys":density}

def dmtcp_trial(kind:str,port:int,root:Path)->dict[str,Any]:
    ckpt=root/f"dmtcp-{kind}";ckpt.mkdir(parents=True);coordinator=7790 if kind=="tool" else 7791
    run(["dmtcp_coordinator","--daemon","--port",str(coordinator)]);process=subprocess.Popen(["dmtcp_launch","--coord-port",str(coordinator),"--ckptdir",str(ckpt),sys.executable,"-m","transactional_inference_state.stage15a_service",kind,"--port",str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True);wait(port);initial=request(port);before=digest(initial)
    mark=time.perf_counter_ns();checkpoint=run(["dmtcp_command","--coord-port",str(coordinator),"--checkpoint"]);checkpoint_ns=time.perf_counter_ns()-mark;time.sleep(1);mutate(kind,port);mutated=request(port);stop(process.pid);images=glob.glob(str(ckpt/"ckpt_*.dmtcp"));mark=time.perf_counter_ns();restart=run(["dmtcp_restart","--coord-port",str(coordinator),*images]);restore_ns=time.perf_counter_ns()-mark;time.sleep(1)
    try:restored=request(port);success=digest(restored)==before and digest(mutated)!=before
    except Exception:restored=None;success=False
    return {"backend":"DMTCP","kind":kind,"checkpoint_success":checkpoint.returncode==0 and bool(images),"restore_command_success":restart.returncode==0,"success":success,"initial":initial,"mutated":mutated,"restored":restored,"checkpoint_ns":checkpoint_ns,"restore_ns":restore_ns,"image_bytes":sum(Path(x).stat().st_size for x in images),"failure":"restart exited without restored participant" if not success else None,"privileged":False}

def main()->None:
    destination=Path(sys.argv[1] if len(sys.argv)>1 else "evaluation_results/stage15a_linux");destination.mkdir(parents=True,exist_ok=True);scratch=Path(tempfile.mkdtemp(prefix="stage15a-linux-"))
    checks={"distribution":Path("/etc/os-release").read_text(),"kernel":platform.release(),"architecture":platform.machine(),"python":platform.python_version(),"euid":os.geteuid(),"capabilities":run(["capsh","--print"]).stdout,"filesystem":run(["df","-T",str(scratch)]).stdout,"criu_version":run(["criu","--version"]).stdout,"criu_check":run(["criu","check"]).stdout+run(["criu","check"]).stderr,"criu_check_all":run(["criu","check","--all"]).stdout+run(["criu","check","--all"]).stderr,"dmtcp_version":run(["dmtcp_launch","--version"]).stdout+run(["dmtcp_launch","--version"]).stderr,"container":Path("/.dockerenv").exists()}
    trials=[criu_trial("tool",18190,scratch),criu_trial("rag",18191,scratch),dmtcp_trial("tool",18192,scratch),dmtcp_trial("rag",18193,scratch)]
    performance=[]
    for size in (1,10,50,100):
        for iteration in range(5):performance.append(criu_trial("tool",18200+iteration,scratch,size_mb=size))
    density=[criu_trial("tool",18300+i,scratch,size_mb=1,density=value) for i,value in enumerate((1,100,10000))]
    result={"environment":checks,"trials":trials,"performance":performance,"mutation_density":density,"criu_status":"AVAILABLE_AND_SUPPORTED" if all(x["success"] for x in trials[:2]) else "AVAILABLE_WITH_LIMITATIONS","dmtcp_status":"AVAILABLE_WITH_LIMITATIONS" if any(x.get("checkpoint_success") for x in trials[2:]) else "UNAVAILABLE"}
    destination.mkdir(parents=True,exist_ok=True);(destination/"native_results.json").write_text(json.dumps(result,indent=2,sort_keys=True));print(json.dumps({"trials":trials,"criu_status":result["criu_status"],"dmtcp_status":result["dmtcp_status"]},indent=2))
if __name__=="__main__":main()
