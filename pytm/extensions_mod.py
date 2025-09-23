from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Iterable, Any
import json
from collections import defaultdict


@dataclass(frozen=False)
class VulnerabilityPattern:
    src_function_type: str
    src_element_type: str
    dst_function_type: str
    dst_element_type: str


@dataclass
class AttackScenarioSpec:
    scenario_id : str
    scenario_name : str
    sub_phases : List[VulnerabilityPattern]

class ScenarioMatch:
    def __init__(self,scenario_id,scenario_name,steps,start):
        self.scenario_id = scenario_id
        self.scenario_name =scenario_name
        self.steps = steps
        self.start = start

class ThreatPathEngine:
    def __init__(self, threat_model,scenarios_path):
        self.threat_model = threat_model                             # pytm TM object
        
        with open(scenarios_path, "r", encoding="utf-8") as f:
            scenario_json = json.load(f)                             # open scenario file(json) in threatlib/...
        
        attack_scenarios = []

        for scenario in scenario_json:
            attack_steps = []
            last_steps = []
            for attack_step in scenario['phases']:
                pattern = VulnerabilityPattern(
                    src_function_type=attack_step["src"][0],
                    src_element_type=attack_step["src"][1],
                    dst_function_type=attack_step["dst"][0],
                    dst_element_type=attack_step["dst"][1],
                )
                attack_steps = attack_steps + [pattern]
            attack_scenarios = attack_scenarios + [AttackScenarioSpec(scenario_id=scenario["id"], scenario_name=scenario["name"],sub_phases=attack_steps)]
        self.scenarios = attack_scenarios

    def debug_check_type_of_asset(self):
        asset_type_str = ""
        for asset in self.threat_model._assets:
            asset_type_str = asset_type_str + " " + str(asset.__class__.__name__)
        with open("asset_tpye.txt", "w", encoding="utf-8") as f:
            f.write(str(asset_type_str)) 

    def result2json(self,results):
        identified_scenarios = {}
        sc_idx=1
        for r in results:
            scenario ={
                "scenario id" : r.scenario_id, "scenario name" : r.scenario_name, "start node" : { "name" : r.start.name, "element_type" :  r.start.__class__.__name__, "function_type" : r.start.function_type}
            }
            steps = {}
            step_idx = 1
            for s in r.steps:
                step = { 
                "source" : {"source_name" : s.source.name, "source_elem_type" : s.source.__class__.__name__, "source_func_type" : s.source.function_type}, 
                "sink" : {" sink_name" : s.sink.name, "sink_elem_type" : s.sink.__class__.__name__, "sink_func_type" : s.sink.function_type}
                }
                steps["step_"+ str(step_idx)] = step
                step_idx =  step_idx + 1
            scenario["steps"] = steps
            identified_scenarios["scenario_"+str(sc_idx)] = scenario
            sc_idx = sc_idx + 1
        with open("identified_scenario.json", "w", encoding="utf-8") as f:
            json.dump(identified_scenarios, f, indent=4, ensure_ascii=False)


    def debug_result2json(self,result_data,target):
        record = []
        for data in result_data:
            if isinstance(data,target):
                record = record + [data.function_type]  
        with open("asset.txt", "w", encoding="utf-8") as f:
            f.write(str(record))   

    
    def find_one(self, scenario, starts):
        for start in starts:
            ## print(start)
            scenario_sub_phases_check = [[obj, False] for obj in scenario.sub_phases]    ##
            scenario_last_check = [[obj, False] for obj in scenario.last]                 ##
            trace = self._search_from(
                current_node=start,                                      ## 현재 노드
                patterns=scenario_sub_phases_check,                      ## 마지막 공격 단계 제외한 나머지 선행 단계들
                last_phases = scenario_last_check,                       ## 마지막 공격 단계
                current_traces = [],
                                       ## 시작점(start)에서부터 DFD를 순회하면서 Flow는 반드시 상승 
            )
            for patt, flag in scenario_sub_phases_check:
                if not flag:
                    trace = None
            for patt, flag in scenario_last_check:
                if not flag:
                    trace = None
            ## print(trace) 결과 위 부분에서 문제 생김
            if trace is not None:
                return ScenarioMatch(scenario_id = scenario.scenario_id, scenario_name=scenario.scenario_name, steps=trace, start = start)          # 식별된 공격 경로(trace)가 있는 경우에만 해당 공격 경로를 반환 
        return None          


    ## find_all : 현재 시스템 모델(self.model)에 대하여 부합하는 공격 시나리오의 패턴이 있는지 확인
    ## @param
    ## - scenarios : 공격 시나리오들의 집합 (json 형식)
    ## @return
    ## - List[ScenarioMatch] : 식별된 공격 시나리오 상의 취약점 패턴의 집합 
    def find_all(self, starts):
        matches = list()
        for sc in self.scenarios:
            ## 현재 시스템 모델(self.model) 상에 각각의 시나리오(sc)에 부합하는 공격 패턴이 있는지 확인 
            m = self.find_one(sc,starts)
            ## print(m)
            ## 부합하는 공격 패턴(m) 확인
            if m is not None:
                matches.append(m)
        return matches
    

    def find_all_test(self):
        matches = list()
        for sc in self.scenarios:
            ## 현재 시스템 모델(self.model) 상에 각각의 시나리오(sc)에 부합하는 공격 패턴이 있는지 확인 
            m = self.find_one_copy(sc)
            ## print(m)
            ## 부합하는 공격 패턴(m) 확인
            if m is not None:
                matches.append(m)
        return matches


    def find_one_copy(self, scenario):
        starts = []
        for asset in self.threat_model._assets:
            ## DFD elements without a 'function_type' listed are excluded from the initial candidate pool.
            if not('function_type' in asset.__dict__) : 
                continue
            for sub_phase in scenario.sub_phases:
                ## Only DFD elements with a 'function_type' listed are included from the initial candidate pool.
                if ((sub_phase.src_function_type == asset.function_type) and (sub_phase.src_element_type == asset.__class__.__name__)) :
                    starts = starts + [asset]
                    continue

        for start in starts:
            ## Pattern matching for each candidate node
            scenario_sub_phases_check = [[obj, False] for obj in scenario.sub_phases]   
            scenario_last_check = [[obj, False] for obj in scenario.last]               
            trace = self._search_from(
                current_node=start,                                      ## current node
                patterns=scenario_sub_phases_check,                      ## 마지막 공격 단계 제외한 나머지 선행 단계들
                last_phases = scenario_last_check,                       ## 
                current_traces = [],                                    
                flow_traversal_strat = 1                                 ## 식별된 공격 경로
                                                                         
            )
            for patt, flag in scenario_sub_phases_check:
                if not flag:
                    trace = None
            for patt, flag in scenario_last_check:
                if not flag:
                    trace = None
            if trace is not None:
                return ScenarioMatch(scenario_id = scenario.scenario_id, scenario_name=scenario.scenario_name, steps=trace, start = start)          # 식별된 공격 경로(trace)가 있는 경우에만 해당 공격 경로를 반환 
        return None                  


    
    def order_by_flow_traversal_strat(self, outflows):
        ordered_outflows = []
        filtered_outflows = [f for f in outflows if f.order >= 1]
        ordered_outflows = sorted(filtered_outflows, key=lambda f: f.order)
        return ordered_outflows 

    def _search_from(self,current_node,patterns,last_phases,current_traces):
        ## search outbound dataflows from this node(current_node) and sort by its order
        outflows = []
        for flow in self.threat_model._flows:
            if flow.source is current_node:
                outflows = outflows + [flow]
                ##with open("find.txt", "w", encoding="utf-8") as f:
                ##    f.write(str(flow.source))  
        ordered_outflows = self.order_by_flow_traversal_strat(outflows)

        if len(ordered_outflows) == 0 :         
            return current_traces  

        for flow in ordered_outflows :
            skip_this_flow = False
            for trace in current_traces:
                if trace == flow :
                    skip_this_flow = True
            
            if skip_this_flow == False:
                for patt in patterns :
                    if (patt[0].src_element_type==str(current_node.__class__.__name__) and patt[0].src_function_type == current_node.function_type 
                        and patt[0].dst_element_type==str(flow.sink.__class__.__name__) and patt[0].dst_function_type == flow.sink.function_type) :
                        current_traces = current_traces + [flow] 
                        patt[1] = True

                        current_traces = self._search_from(current_node = flow.sink,patterns = patterns, last_phases = last_phases,current_traces = current_traces, flow_traversal_strat=1)

                for patt in last_phases : 
                    if (patt[0].src_element_type==str(current_node.__class__.__name__) and patt[0].src_function_type == current_node.function_type 
                        and patt[0].dst_element_type==str(flow.sink.__class__.__name__) and patt[0].dst_function_type == flow.sink.function_type) :
                        current_traces = current_traces + [flow] 
                        patt[1] = True
                        
        
        return current_traces


## (아래 수정 필요)

def find_read_then_write(tm_instance):
    """
    DataFlow Diagram에서 Data Store에 대해 'Read' 작업이 'Write' 작업보다
    먼저 발생하는 패턴을 찾는 알고리즘입니다.

    Args:
        tm_instance (TM): pytm.py의 TM 클래스 인스턴스.

    Returns:
        dict: 패턴이 발견된 Data Store와 해당 패턴의 Dataflow 연결 정보를 담은 딕셔너리.
    """
    found_patterns = defaultdict(list)
    
    # 1. 모든 Data Store 요소를 찾음
    data_stores = [e for e in tm_instance._elements if isinstance(e, Datastore)]
    
    print("## Data Store 요소 탐색 시작...")
    print(f"총 {len(data_stores)}개의 Data Store 발견: {[ds.name for ds in data_stores]}")

    # 2. 각 Data Store에 연결된 Dataflow를 순회
    for ds in data_stores:
        print(f"\n### {ds.name} Data Store 연결 분석...")
        # Data Store가 source 또는 sink인 모든 Dataflow를 가져옴
        related_flows = [
            f for f in tm_instance._flows if f.source is ds or f.sink is ds
        ]
        
        # Data Store와 연결된 'Read' 및 'Write' Dataflow를 분류합니다.
        read_flows = [
            f for f in related_flows if 'read' in f.note.lower()
        ]
        write_flows = [
            f for f in related_flows if 'write' in f.note.lower()
        ]
        
        if not read_flows or not write_flows:
            print(f"  - {ds.name}에는 Read 또는 Write Dataflow가 부족합니다. 스킵합니다.")
            continue

        print(f"  - Read Dataflow ({len(read_flows)}개): {[f.display_name() for f in read_flows]}")
        print(f"  - Write Dataflow ({len(write_flows)}개): {[f.display_name() for f in write_flows]}")

        # 3. Read Dataflow와 Write Dataflow 쌍을 조합하여 순서를 확인합니다.
        for read_flow in read_flows:
            for write_flow in write_flows:
                # 'order' 속성값을 비교하여 'Read'가 'Write'보다 순서가 빠른지 확인합니다.
                # order 값이 작을수록 순서가 빠름을 의미합니다.
                if read_flow.order < write_flow.order:
                    # 패턴이 발견되면 기록합니다.
                    pattern_info = {
                        "data_store": ds.name,
                        "read_flow": read_flow.display_name(),
                        "write_flow": write_flow.display_name(),
                        "read_order": read_flow.order,
                        "write_order": write_flow.order
                    }
                    found_patterns[ds.name].append(pattern_info)
                    print(f"  - 🔴 패턴 발견! {read_flow.display_name()} (Read)가 {write_flow.display_name()} (Write)보다 먼저 발생합니다.")

    return found_patterns


def