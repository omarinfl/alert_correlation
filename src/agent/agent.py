from typing import Annotated, TypedDict
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, BaseMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from src.agent.tools import query_mitre, query_cve

class AgentState(TypedDict):
    messages: Annotated[BaseMessage, add_messages]

llm = ChatOllama(model='llama3.1:8b')

available_tools = [query_cve, query_mitre]
llm_with_tools = llm.bind_tools(available_tools)

def agent_node(state: AgentState):
    '''Agent node that processes messages and generates a response.'''
    messages = state['messages']
    instructions = SystemMessage(content='''
                                 You are a SOC expert analyst. Your work is to analyze security alerts, logs and
                                 threat intelligence to identify potential security incidents and recommend appropriate responses.
                                 YOU HAVE TOOLS AVAILABLE TO YOU, USE THEM WHEN NECESSARY TO COMPLETE YOUR TASKS.
                                 They allow you to query databases, CVE for vulnerabilities, and MITRE for attack techniques, among other things. 
                                 Always use them when you need to retrieve information to complete your tasks.
                                 Answer in a structured, professional and concise way.
                                 ''')
    if len(messages) == 1:
        # If it's the first message, add the system instructions
        messages = [instructions] + messages

    response = llm_with_tools.invoke(messages)
    return {'messages': [response]}


def use_tool_decision(state: AgentState):
    '''Decision node that determines whether the agent should use a tool or not.'''
    last_message = state['messages'][-1]
    
    if hasattr(last_message, 'tool_calls') and len(last_message.tool_calls) > 0:
        return 'action'
    
    return 'end'

workflow = StateGraph(AgentState)
workflow.add_node('agent', agent_node)
workflow.add_node('action', ToolNode(available_tools))
workflow.set_entry_point('agent')
workflow.add_conditional_edges(
    'agent',
    use_tool_decision,
    {
        'action': 'action',
        'end': END
    }
)

workflow.add_edge('action', 'agent')
app = workflow.compile()

if __name__ == "__main__":    
    print('SOC Agent is ready to receive messages. Type "exit" or "quit" to stop the agent.')
    while True:
        user_input = input("\nUser: ")
        if user_input.lower() in ['exit', 'quit']:
            print("Exiting SOC Agent.")
            break

        inputs = {'messages': [HumanMessage(content=user_input)]}
        for event in app.stream(inputs, stream_mode='values'):
            last_message = event['messages'][-1]
            if hasattr(last_message, 'content') and last_message.content and not hasattr(last_message, 'tool_calls'):
                print(f"Agent: {last_message.content}")
