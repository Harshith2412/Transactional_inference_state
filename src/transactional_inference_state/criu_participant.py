"""Minimal CRIU adapter for validated single-process localhost participants."""
from __future__ import annotations
import json,os,shutil,signal,subprocess,time,urllib.request
from pathlib import Path
from typing import Any
from .stage15a import canonical_digest
from .stage15a3 import CheckpointHandle,ParticipantEligibility,ProcessScope
from .stage15b import RestoreResult

class CRIUCheckpointParticipant:
 def __init__(self,participant_id:str,pid:int,endpoint:str,checkpoint_root:str|Path,eligibility:ParticipantEligibility):self.participant_id=participant_id;self.pid=pid;self.endpoint=endpoint.rstrip('/');self.root=Path(checkpoint_root);self.root.mkdir(parents=True,exist_ok=True);self._eligibility=eligibility;self.sequence=0;self._snapshots={};self.connected=True;self.last_metrics={}
 def eligibility(self):return self._eligibility
 def quiesce(self):pass
 def resume(self):pass
 def checkpoint(self):
  state=self._get('/state');self.sequence+=1;directory=self.root/f'{self.participant_id}-{self.sequence:06d}-{time.time_ns()}';directory.mkdir();start=time.perf_counter_ns();result=subprocess.run(['criu','dump','-t',str(self.pid),'-D',str(directory),'--shell-job','--tcp-established','--leave-running','-o','dump.log'],capture_output=True,text=True);elapsed=time.perf_counter_ns()-start
  if result.returncode or not (directory/'inventory.img').is_file():raise RuntimeError(result.stderr or 'CRIU checkpoint image missing')
  handle=CheckpointHandle('CRIU',self.participant_id,str(directory),canonical_digest(state),self.sequence,str(self.pid),self.endpoint,ProcessScope.SINGLE_PROCESS);self._snapshots[handle.metadata_hash()]=state;self.last_metrics={'checkpoint_ns':elapsed,'checkpoint_bytes':sum(x.stat().st_size for x in directory.rglob('*') if x.is_file())};return handle
 def invalidate_client(self):self.connected=False
 def restore(self,handle):
  try:os.kill(self.pid,signal.SIGKILL);os.waitpid(self.pid,0)
  except (ProcessLookupError,ChildProcessError):pass
  directory=Path(handle.checkpoint_path);pidfile=directory/'restored.pid';start=time.perf_counter_ns();result=subprocess.run(['criu','restore','-D',str(directory),'--shell-job','--tcp-established','-d','--pidfile',str(pidfile),'-o','restore.log'],capture_output=True,text=True);self.last_metrics['restore_ns']=time.perf_counter_ns()-start
  if result.returncode:return RestoreResult(False,False,False,False,False,False,result.stderr or 'CRIU restore failed')
  self.pid=int(pidfile.read_text());reachable=self._wait();state=self._get('/state') if reachable else None;expected=self._snapshots.get(handle.metadata_hash());equal=state==expected;matching=state is not None and canonical_digest(state)==handle.state_digest;return RestoreResult(True,reachable,reachable,equal,matching,reachable,None if matching else 'state oracle mismatch')
 def reconnect(self):self.connected=self._wait()
 def health_check(self):return self.connected and self._wait()
 def verify_state(self,handle):
  try:return canonical_digest(self._get('/state'))==handle.state_digest
  except Exception:return False
 def release(self,handle):shutil.rmtree(handle.checkpoint_path);self._snapshots.pop(handle.metadata_hash(),None)
 def _get(self,path):
  with urllib.request.urlopen(self.endpoint+path,timeout=2) as response:return json.load(response)
 def _wait(self):
  for _ in range(100):
   try:self._get('/state');return True
   except Exception:time.sleep(.05)
  return False
