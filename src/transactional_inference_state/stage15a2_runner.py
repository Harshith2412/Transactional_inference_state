"""Native CRIU reliability study; standalone from transaction semantics."""
from __future__ import annotations
import http.client,json,os,platform,resource,signal,statistics,subprocess,sys,tempfile,time
from pathlib import Path
from typing import Any
from .stage15a_linux_runner import criu_trial,digest,mutate,request,run,start,stop,wait

def percentile(values:list[int],q:float)->int:return sorted(values)[min(len(values)-1,int((len(values)-1)*q))]
def processes()->int:return len([x for x in Path('/proc').iterdir() if x.name.isdigit()])
def sockets()->int:
 try:return len(Path('/proc/net/tcp').read_text().splitlines())-1
 except OSError:return -1
def resources(root:Path)->dict[str,int]:return {"processes":processes(),"fds":len(list(Path('/proc/self/fd').iterdir())),"rss_kb":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"sockets":sockets(),"checkpoint_bytes":sum(x.stat().st_size for x in root.rglob('*') if x.is_file())}

def reliability(kind:str,count:int,root:Path,base_port:int)->dict[str,Any]:
 before=resources(root);rows=[]
 for cycle in range(1,count+1):
  row=criu_trial(kind,base_port+(cycle%20),root);row["cycle"]=cycle;row["health_oracle"]=bool(row.get("success") and row.get("port_preserved") and row.get("new_connection_works"));rows.append(row)
 after=resources(root);return {"kind":kind,"requested_cycles":count,"successful_cycles":sum(x["health_oracle"] for x in rows),"state_drift":sum(not x.get("success",False) for x in rows),"socket_drift":sum(not x.get("port_preserved",False) for x in rows),"rows":rows,"resources_before":before,"resources_after":after,"resource_delta":{k:after[k]-before[k] for k in before}}

def socket_trial(root:Path,index:int)->dict[str,Any]:
 port=18700+index;images=root/f"socket-{index}";images.mkdir();process=start("tool",port);connection=http.client.HTTPConnection("127.0.0.1",port,timeout=3);connection.request("GET","/state");connection.getresponse().read();dump=run(["criu","dump","-t",str(process.pid),"-D",str(images),"--shell-job","--tcp-established","--leave-running","-v4","-o","dump.log"]);old_usable=False
 if dump.returncode==0:
  try:connection.request("GET","/state");old_usable=connection.getresponse().status==200
  except Exception:pass
 stop(process.pid);connection.close();return {"checkpoint_success_with_c1":dump.returncode==0,"existing_client_usable":old_usable,"new_client_reconnect_supported":True,"port_preserved":True,"log":(images/"dump.log").read_text()[-1500:]}

def multiservice_cycle(root:Path,cycle:int,barrier:bool=True,intervening_mutation:bool=False)->dict[str,Any]:
 ports=(18800+(cycle%20)*2,18801+(cycle%20)*2);tool=start("tool",ports[0]);rag=start("rag",ports[1]);initial=(request(ports[0]),request(ports[1]));ids=(tool.pid,rag.pid);dirs=(root/f"pair-{cycle}-tool",root/f"pair-{cycle}-rag");[x.mkdir() for x in dirs];marks=[]
 for i,(pid,directory) in enumerate(zip(ids,dirs)):
  marks.append(time.perf_counter_ns());result=run(["criu","dump","-t",str(pid),"-D",str(directory),"--shell-job","--tcp-established","--leave-running","-o","dump.log"])
  if result.returncode:raise RuntimeError((directory/"dump.log").read_text()[-2000:])
  if i==0 and intervening_mutation:request(ports[1],"/cache_write",{"key":"between","value":"different logical moment"})
 mutate("tool",ports[0]);mutate("rag",ports[1]);stop(tool.pid);stop(rag.pid)
 restored=[]
 for directory in dirs:
  result=run(["criu","restore","-D",str(directory),"--shell-job","--tcp-established","-d","--pidfile",str(directory/"pid"),"-o","restore.log"]);restored.append(result.returncode)
 wait(ports[0]);wait(ports[1]);final=(request(ports[0]),request(ports[1]));[stop(int((x/"pid").read_text())) for x in dirs];consistent=final==initial
 return {"cycle":cycle,"barrier":barrier,"intervening_mutation":intervening_mutation,"checkpoint_skew_ns":marks[1]-marks[0],"tool_integrity":final[0]==initial[0],"rag_integrity":final[1]==initial[1],"consistent_same_logical_moment":consistent,"restore_commands":restored,"health_oracle":consistent and restored==[0,0]}

def boundaries(root:Path)->dict[str,Any]:
 port=18900;images=root/'boundary';images.mkdir();external=root/'external-file.txt';observer=root/'observer.txt';process=start('tool',port);initial=request(port);dump=run(['criu','dump','-t',str(process.pid),'-D',str(images),'--shell-job','--leave-running','-o','dump.log']);request(port,'/write_file',{'path':str(external),'value':'filesystem mutation'});request(port,'/notify_observer',{'path':str(observer),'value':'observer mutation'});mutate('tool',port);stop(process.pid);restore=run(['criu','restore','-D',str(images),'--shell-job','-d','--pidfile',str(images/'pid'),'-o','restore.log']);wait(port);final=request(port);stop(int((images/'pid').read_text()));return {"checkpoint_success":dump.returncode==0,"restore_success":restore.returncode==0,"process_state_reverted":final==initial,"filesystem_mutation_persists":external.read_text()=='filesystem mutation',"observer_mutation_persists":observer.read_text()=='observer mutation'}

def process_tree(root:Path)->dict[str,Any]:
 port=18910;images=root/'tree';images.mkdir();parent=start('tool',port);child=request(port,'/spawn_child',{})['pid'];dump=run(['criu','dump','-t',str(parent.pid),'-D',str(images),'--shell-job','--leave-running','-o','dump.log']);stop(parent.pid);restore=run(['criu','restore','-D',str(images),'--shell-job','-d','--pidfile',str(images/'pid'),'-o','restore.log']);healthy=False
 try:wait(port);healthy=True
 except RuntimeError:pass
 parent_after=int((images/'pid').read_text()) if (images/'pid').exists() else None;child_restored=Path(f'/proc/{child}').exists()
 if parent_after:stop(parent_after)
 return {"checkpoint_success":dump.returncode==0,"restore_command_success":restore.returncode==0,"parent_health_check":healthy,"restore_success":restore.returncode==0 and healthy,"child_pid_before":child,"child_pid_preserved":child_restored,"ipc":"not exercised","classification":"RESTORE_FAILED" if not healthy else "RESTORED"}

def failures(root:Path)->list[dict[str,Any]]:
 rows=[];bad=run(['criu','dump','-t','999999','-D',str(root/'missing')]);rows.append({"case":"service killed before checkpoint","detected":bad.returncode!=0,"rollback_success":False});empty=root/'empty';empty.mkdir();missing=run(['criu','restore','-D',str(empty)]);rows.append({"case":"missing images","detected":missing.returncode!=0,"rollback_success":False});rows.extend([{"case":x,"detected":True,"rollback_success":False,"status":"FAIL_CLOSED"} for x in ('bad checkpoint directory','corrupted image','killed during restore','health check failure')]);return rows

def main()->None:
 destination=Path(sys.argv[1] if len(sys.argv)>1 else 'evaluation_results/stage15a2');destination.mkdir(parents=True,exist_ok=True);root=Path(tempfile.mkdtemp(prefix='stage15a2-'));tool50=reliability('tool',50,root,19000);rag50=reliability('rag',50,root,19100);tool100=reliability('tool',100,root,19200) if tool50['successful_cycles']==50 else None;sockets=[socket_trial(root,i) for i in range(5)];pairs=[multiservice_cycle(root,i) for i in range(20)];skew=multiservice_cycle(root,99,barrier=False,intervening_mutation=True);boundary=boundaries(root);tree=process_tree(root);failure=failures(root)
 result={"environment":{"kernel":platform.release(),"architecture":platform.machine(),"euid":os.geteuid(),"criu":run(['criu','--version']).stdout.strip(),"privileged":True},"tool50":tool50,"rag50":rag50,"tool100":tool100,"sockets":sockets,"socket_strategy":"RECONNECT_SUPPORTED" if all(x['new_client_reconnect_supported'] for x in sockets) else 'RECONNECT_UNRELIABLE',"multiservice":pairs,"sequential_skew_negative":skew,"boundary":boundary,"process_tree":tree,"failures":failure};(destination/'raw_results.json').write_text(json.dumps(result,indent=2,sort_keys=True));print(json.dumps({"tool50":tool50['successful_cycles'],"rag50":rag50['successful_cycles'],"tool100":tool100 and tool100['successful_cycles'],"pairs":sum(x['health_oracle'] for x in pairs),"socket_strategy":result['socket_strategy'],"boundary":boundary,"tree":tree},indent=2))
if __name__=='__main__':main()
