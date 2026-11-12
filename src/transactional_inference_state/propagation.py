"""Trusted runtime-dataflow provenance propagation; no semantic inference."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .cow import FieldPath
from .effects import TransactionalTools
from .lineage import LineageGraph, LineageNode, LineageNodeType, StateReference
from .provenance import RuntimeSourceType, TrustLabel


class DataflowOperation(str,Enum):
    RETRIEVE="RETRIEVE";CONCAT="CONCAT";SUMMARIZE="SUMMARIZE";SELECT_FIELD="SELECT_FIELD"
    FILTER="FILTER";CACHE_WRITE="CACHE_WRITE";CACHE_READ="CACHE_READ";MEMORY_WRITE="MEMORY_WRITE"
    MEMORY_READ="MEMORY_READ";TOOL_CALL="TOOL_CALL";CONTEXT_BUILD="CONTEXT_BUILD";EFFECT_BUILD="EFFECT_BUILD"


class PropagationRule(str,Enum):
    IDENTITY="identity";UNION="union";FIELD_SELECT="field_select";FIELD_FILTER="field_filter";STATE="state";EFFECT="effect"


class TransformRegistry:
    """Fixed trusted transform-to-propagation-rule mapping."""
    def __init__(self)->None:
        self._rules={DataflowOperation.RETRIEVE:PropagationRule.IDENTITY,
          DataflowOperation.CONCAT:PropagationRule.UNION,DataflowOperation.SUMMARIZE:PropagationRule.UNION,
          DataflowOperation.SELECT_FIELD:PropagationRule.FIELD_SELECT,DataflowOperation.FILTER:PropagationRule.FIELD_FILTER,
          DataflowOperation.CACHE_WRITE:PropagationRule.STATE,DataflowOperation.CACHE_READ:PropagationRule.IDENTITY,
          DataflowOperation.MEMORY_WRITE:PropagationRule.STATE,DataflowOperation.MEMORY_READ:PropagationRule.IDENTITY,
          DataflowOperation.TOOL_CALL:PropagationRule.UNION,DataflowOperation.CONTEXT_BUILD:PropagationRule.UNION,
          DataflowOperation.EFFECT_BUILD:PropagationRule.EFFECT}
    def rule(self,operation:DataflowOperation)->PropagationRule:return self._rules[operation]
    @property
    def operations(self)->tuple[DataflowOperation,...]:return tuple(self._rules)


@dataclass(frozen=True)
class TrackedValue:
    value:Any
    source_ids:tuple[str,...]
    node_id:str
    verified:bool=True
    field_sources:dict[str,tuple[str,...]]=field(default_factory=dict)
    field_nodes:dict[str,str]=field(default_factory=dict)


@dataclass(frozen=True)
class ProvenanceGap:
    gap_id:str
    operation:str
    transaction_id:str
    reason:str


class ProvenanceEngine:
    """Infers ancestry only from explicit trusted runtime dataflow calls."""
    def __init__(self,manager:Any,session_id:str,*,graph:LineageGraph|None=None,
                 registry:TransformRegistry|None=None)->None:
        self.manager=manager;self.session_id=session_id;self.graph=graph or manager.lineage_graph or LineageGraph()
        self.registry=registry or TransformRegistry();self.transaction_id="";self._next=1
        self._state_nodes:dict[str,str]={};self.gaps:list[ProvenanceGap]=[]
        self.tracked_derived=0;self.authoritative_derived=0;self.dataflow_calls=0
        self.automatic_lineage_edges=0;self.explicit_lineage_calls=0

    def bind(self,transaction_id:str)->"ProvenanceEngine":
        self.transaction_id=transaction_id;return self

    def source(self,value:Any,source_type:RuntimeSourceType,*,trust_label:TrustLabel,
               operation:DataflowOperation=DataflowOperation.RETRIEVE)->TrackedValue:
        self._require_transaction();record=self.manager.issue_provenance(self.transaction_id,source_type,trust_label=trust_label)
        kind={RuntimeSourceType.RETRIEVED_CONTENT:LineageNodeType.RETRIEVAL,RuntimeSourceType.USER_PROMPT:LineageNodeType.USER_INPUT,
              RuntimeSourceType.USER_INPUT:LineageNodeType.USER_INPUT,RuntimeSourceType.TOOL_RESULT:LineageNodeType.TOOL_RESULT}.get(source_type,LineageNodeType.CONTEXT)
        self.graph.add_node(LineageNode(record.source_id,kind,record.user_id,self.session_id,self.transaction_id,record.source_id,trust_label))
        self.dataflow_calls+=1
        fields={k:(record.source_id,) for k in value} if isinstance(value,dict) else {}
        nodes={k:record.source_id for k in fields}
        return TrackedValue(deepcopy(value),(record.source_id,),record.source_id,True,fields,nodes)

    def derive(self,operation:DataflowOperation,inputs:list[TrackedValue|Any],value:Any,*,
               node_type:LineageNodeType=LineageNodeType.MODEL_OUTPUT,
               field_inputs:dict[str,list[TrackedValue]]|None=None)->TrackedValue:
        self._require_transaction();self.registry.rule(operation);self.dataflow_calls+=1;self.tracked_derived+=1
        tracked=[x for x in inputs if isinstance(x,TrackedValue)];verified=len(tracked)==len(inputs) and all(x.verified for x in tracked)
        if not verified:
            gap=self._gap(operation,"raw or unverified transform input")
        parent_sources=_unique(s for item in tracked for s in item.source_ids) if verified else ()
        trust=self._trust(parent_sources) if verified else TrustLabel.UNKNOWN
        record=self.manager.issue_provenance(self.transaction_id,RuntimeSourceType.DERIVED_VALUE,trust_label=trust,parent_source_ids=parent_sources)
        node=self._node(operation.value.lower());self.graph.add_node(LineageNode(node,node_type,self._user(),self.session_id,self.transaction_id,record.source_id,trust,verified_lineage=verified))
        for item in tracked:
            self.graph.add_edge(item.node_id,node,operation.value.lower());self.automatic_lineage_edges+=1
        field_sources:dict[str,tuple[str,...]]={};field_nodes:dict[str,str]={}
        if isinstance(value,dict):
            if field_inputs is None:
                for key in value:field_sources[key]=(record.source_id,);field_nodes[key]=node
            else:
                for key,contributors in field_inputs.items():
                    field_sources[key]=_unique(s for item in contributors for s in item.source_ids)
                    field_nodes[key]=contributors[0].node_id if len(contributors)==1 else node
        if verified:self.authoritative_derived+=1
        return TrackedValue(deepcopy(value),(record.source_id,),node,verified,field_sources,field_nodes)

    def select_field(self,input_value:TrackedValue,field_name:str)->TrackedValue:
        if not isinstance(input_value.value,dict) or field_name not in input_value.value:raise KeyError(field_name)
        sources=input_value.field_sources.get(field_name,())
        if not sources:return self.derive(DataflowOperation.SELECT_FIELD,[input_value.value[field_name]],input_value.value[field_name])
        record=self.manager.issue_provenance(self.transaction_id,RuntimeSourceType.DERIVED_VALUE,trust_label=self._trust(sources),parent_source_ids=sources)
        node=self._node("select");self.graph.add_node(LineageNode(node,LineageNodeType.CONTEXT,self._user(),self.session_id,self.transaction_id,record.source_id,self._trust(sources)))
        parent=input_value.field_nodes.get(field_name,input_value.node_id);self.graph.add_edge(parent,node,"select_field");self.automatic_lineage_edges+=1;self.dataflow_calls+=1;self.tracked_derived+=1;self.authoritative_derived+=1
        return TrackedValue(deepcopy(input_value.value[field_name]),(record.source_id,),node)

    def filter_fields(self,input_value:TrackedValue,fields:tuple[str,...])->TrackedValue:
        selected={k:input_value.value[k] for k in fields if k in input_value.value}
        contributors={k:[TrackedValue(selected[k],input_value.field_sources.get(k,()),input_value.field_nodes.get(k,input_value.node_id),input_value.verified)] for k in selected}
        return self.derive(DataflowOperation.FILTER,list(contributors[k][0] for k in selected),selected,field_inputs=contributors)

    def build_context(self,segments:dict[str,TrackedValue])->TrackedValue:
        return self.derive(DataflowOperation.CONTEXT_BUILD,list(segments.values()),{k:v.value for k,v in segments.items()},node_type=LineageNodeType.CONTEXT,field_inputs={k:[v] for k,v in segments.items()})

    def write_memory(self,path:FieldPath,value:TrackedValue)->TrackedValue:return self._write(DataflowOperation.MEMORY_WRITE,path,value,LineageNodeType.MEMORY)
    def write_cache(self,path:FieldPath,value:TrackedValue)->TrackedValue:return self._write(DataflowOperation.CACHE_WRITE,path,value,LineageNodeType.CACHE)
    def read_memory(self,path:FieldPath)->TrackedValue:return self._read(DataflowOperation.MEMORY_READ,path,LineageNodeType.MEMORY)
    def read_cache(self,path:FieldPath)->TrackedValue:return self._read(DataflowOperation.CACHE_READ,path,LineageNodeType.CACHE)

    def tool_call(self,name:str,inputs:list[TrackedValue],result:Any)->TrackedValue:
        return self.derive(DataflowOperation.TOOL_CALL,inputs,result,node_type=LineageNodeType.TOOL_RESULT)

    def stage_email(self,*,to:str,subject:TrackedValue,body:TrackedValue)->Any:
        effect_value=self.derive(DataflowOperation.EFFECT_BUILD,[subject,body],{"to":to,"subject":subject.value,"body":body.value},node_type=LineageNodeType.EFFECT)
        effect=TransactionalTools(self.manager.effect_manager,self.transaction_id,self.session_id).send_email(to=to,subject=str(subject.value),body=str(body.value),provenance_ids=effect_value.source_ids,dependency_ids=effect_value.source_ids)
        return effect,effect_value

    def uninstrumented(self,value:Any,operation:str="unknown_transform")->TrackedValue:
        self._require_transaction();self.tracked_derived+=1;self.dataflow_calls+=1;self._gap(operation,"transformation occurred outside propagation API")
        record=self.manager.issue_provenance(self.transaction_id,RuntimeSourceType.DERIVED_VALUE,trust_label=TrustLabel.UNKNOWN)
        node=self._node("gap");self.graph.add_node(LineageNode(node,LineageNodeType.MODEL_OUTPUT,self._user(),self.session_id,self.transaction_id,record.source_id,TrustLabel.UNKNOWN,verified_lineage=False))
        return TrackedValue(deepcopy(value),(record.source_id,),node,False)

    @property
    def provenance_coverage(self)->float:return self.authoritative_derived/max(1,self.tracked_derived)
    @property
    def unknown_rate(self)->float:return (self.tracked_derived-self.authoritative_derived)/max(1,self.tracked_derived)

    def _write(self,operation,path,value,kind):
        output=self.derive(operation,[value],value.value,node_type=kind)
        self.manager.write_path(self.transaction_id,self.session_id,path,output.value,provenance_ids=output.source_ids)
        state_node=self._node(operation.value.lower());self.graph.add_node(LineageNode(state_node,kind,self._user(),self.session_id,self.transaction_id,output.source_ids[0],self._trust(output.source_ids),StateReference(self.session_id,path)))
        self.graph.add_edge(output.node_id,state_node,operation.value.lower());self.automatic_lineage_edges+=1;self._state_nodes[path.canonical()]=state_node
        return TrackedValue(output.value,output.source_ids,state_node,output.verified,output.field_sources,output.field_nodes)

    def _read(self,operation,path,kind):
        value=self.manager.read_path(self.transaction_id,self.session_id,path);records=self.manager.provenance_for_path(self.session_id,path);sources=tuple(x.source_id for x in records)
        if not sources:return self.uninstrumented(value,f"{operation.value}:missing_provenance")
        record=self.manager.issue_provenance(self.transaction_id,RuntimeSourceType.MEMORY if kind is LineageNodeType.MEMORY else RuntimeSourceType.DERIVED_VALUE,trust_label=self._trust(sources),parent_source_ids=sources)
        node=self._node(operation.value.lower());self.graph.add_node(LineageNode(node,kind,self._user(),self.session_id,self.transaction_id,record.source_id,self._trust(sources)))
        parent=self._state_nodes.get(path.canonical())
        if parent:self.graph.add_edge(parent,node,operation.value.lower());self.automatic_lineage_edges+=1
        self.dataflow_calls+=1;self.tracked_derived+=1;self.authoritative_derived+=1
        return TrackedValue(value,(record.source_id,),node)

    def _gap(self,operation,reason):
        gap=ProvenanceGap(f"gap-{len(self.gaps)+1:06d}",operation.value if isinstance(operation,DataflowOperation) else str(operation),self.transaction_id,reason);self.gaps.append(gap)
        self.manager.event_log.record("PROVENANCE_GAP",self.transaction_id,session_id=self.session_id,gap_id=gap.gap_id,operation=gap.operation,reason=reason);return gap
    def _trust(self,sources):
        labels={self.manager.provenance_registry.get(x).trust_label for x in sources}
        if not labels:return TrustLabel.UNKNOWN
        return next(iter(labels)) if len(labels)==1 else TrustLabel.MIXED
    def _node(self,prefix):node=f"auto-{prefix}-{self._next:06d}";self._next+=1;return node
    def _user(self):return self.manager.sessions.user_id(self.session_id)
    def _require_transaction(self):
        if not self.transaction_id:raise RuntimeError("bind a transaction before propagation")


def _unique(items):return tuple(dict.fromkeys(items))
