from dataclasses import dataclass, field
from typing import Optional, List, Type, Union

from agent.base import BaseAgent 
from agent.tools.basetool import FlexibleContext, ExecutableTool

@dataclass
class AgentConfig:
    agent_class: Type[BaseAgent] = BaseAgent
    tool_configs: List[Union[Type[ExecutableTool], 'AssistantToolConfig']] = field(default_factory=list)
    system_prompt: Optional[str] = None
    max_iterations: int = 20
    agent_instance_name: Optional[str] = None

@dataclass
class AssistantToolConfig:
    assistant_class: Type[ExecutableTool] 
    sub_agent_config: AgentConfig       
    name: Optional[str] = None
    description: Optional[str] = None

def build_assistant(assistant_config: AssistantToolConfig, context: FlexibleContext) -> ExecutableTool:
    from agent.core.assitants import BaseAssistant, ParallelBaseAssistant

    sub_agent_tool_configs = assistant_config.sub_agent_config.tool_configs if assistant_config.sub_agent_config else []

    if issubclass(assistant_config.assistant_class, (BaseAssistant, ParallelBaseAssistant)):
        agent_to_create = assistant_config.sub_agent_config.agent_class if assistant_config.sub_agent_config and assistant_config.sub_agent_config.agent_class else BaseAgent
        return assistant_config.assistant_class(
            context=context,
            name=assistant_config.name,
            agent_class_to_create=agent_to_create,
            default_sub_agent_tool_classes=sub_agent_tool_configs,
            default_sub_agent_max_iterations=assistant_config.sub_agent_config.max_iterations if assistant_config.sub_agent_config else 10,
            sub_agent_system_prompt=assistant_config.sub_agent_config.system_prompt if assistant_config.sub_agent_config else None,
            description=assistant_config.description
        )
    else:
        print(f"Warning: Assistant class {assistant_config.assistant_class.__name__} is not a subclass of BaseAssistant or ParallelBaseAssistant. Attempting generic instantiation.")
        try:
            kwargs = {'context': context, 'name': assistant_config.name}
            if assistant_config.description is not None:
                kwargs['description'] = assistant_config.description
            return assistant_config.assistant_class(**kwargs)
        except TypeError as e:
             raise TypeError(f"Failed to instantiate {assistant_config.assistant_class.__name__} with generic parameters (context, name, description?). Specific handling needed or check class definition. Error: {e}")


def build_agent(agent_config: AgentConfig, context: FlexibleContext) -> BaseAgent:
    agent_tools = []
    if agent_config.tool_configs:
        for tool_conf_or_class in agent_config.tool_configs:
            if isinstance(tool_conf_or_class, AssistantToolConfig):
                agent_tools.append(build_assistant(tool_conf_or_class, context))
            else:
                agent_tools.append(tool_conf_or_class)
            
    return agent_config.agent_class(
        context=context,
        tools=agent_tools,
        system_prompt=agent_config.system_prompt,
        max_iterations=agent_config.max_iterations,
        agent_instance_name=agent_config.agent_instance_name
    ) 